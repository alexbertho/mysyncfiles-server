"""Exercise the actual TCP gate and transactional deployment failure boundaries."""

import asyncio
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy/cicd" / f"{name}.py")
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


gateway = module("gateway")
deploy = module("deploy")


@contextlib.contextmanager
def database(path):
    with contextlib.closing(sqlite3.connect(path)) as connection:
        with connection:
            yield connection


class GatewayTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []
        self.requests = []
        self.release = asyncio.Event()
        self.entered = asyncio.Event()
        self.old = await self.backend("old")
        self.new = await self.backend("new")
        self.gate = gateway.Gateway(self.old, queue_timeout=2)
        self.front = await asyncio.start_server(self.gate.proxy, "127.0.0.1", 0)
        self.port = self.front.sockets[0].getsockname()[1]
        self.servers.append(self.front)

    async def asyncTearDown(self):
        self.release.set()
        for server in self.servers:
            server.close()
            await server.wait_closed()
        for _attempt in range(100):
            if not self.gate.connections:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(self.gate.connections, 0)

    async def backend(self, version):
        async def handle(reader, writer):
            try:
                header = await reader.readuntil(b"\r\n\r\n")
                size = int(next(line.split(b":", 1)[1] for line in header.split(b"\r\n")
                                if line.lower().startswith(b"content-length:")))
                if b" /slow " in header:
                    self.entered.set()
                    await self.release.wait()
                body = await reader.readexactly(size)
                self.requests.append((version, body))
                response = version.encode() + b":" + hashlib.sha256(body).hexdigest().encode()
                writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                             + str(len(response)).encode() + b"\r\n\r\n" + response)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def post(self, body=b"write once", path="/upload", half_close=False):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(f"POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode())
        for offset in range(0, len(body), 16384):
            writer.write(body[offset:offset + 16384])
            await writer.drain()
        if half_close:
            writer.write_eof()
        response = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        await writer.wait_closed()
        return response

    async def test_inflight_transfer_finishes_and_queued_post_reaches_new_version_once(self):
        slow = asyncio.create_task(self.post(b"already in progress", "/slow"))
        await asyncio.wait_for(self.entered.wait(), 1)
        await self.gate.pause()
        drain = asyncio.create_task(self.gate.drain(1))
        body = bytes(range(256)) * 8192
        pending = asyncio.create_task(self.post(body))
        await asyncio.sleep(0.05)
        self.assertFalse(drain.done())
        self.assertFalse(pending.done())
        self.assertEqual(self.gate.active, 1)
        self.release.set()
        self.assertIn(b"old:", await slow)
        await drain
        self.assertEqual(self.requests, [("old", b"already in progress")])
        await self.gate.resume(self.new)
        self.assertIn(b"new:" + hashlib.sha256(body).hexdigest().encode(), await pending)
        self.assertEqual(self.requests, [("old", b"already in progress"), ("new", body)])

    async def test_drain_timeout_preserves_active_request_and_allows_abort(self):
        slow = asyncio.create_task(self.post(b"still transferring", "/slow"))
        await asyncio.wait_for(self.entered.wait(), 1)
        await self.gate.pause()
        with self.assertRaises(asyncio.TimeoutError):
            await self.gate.drain(0.02)
        await self.gate.resume(self.old)
        self.assertIn(b"old:", await self.post())
        self.release.set()
        self.assertIn(b"old:", await slow)

    async def test_half_closed_client_receives_the_complete_response(self):
        body = b"half-closed request" * 10000
        response = await self.post(body, half_close=True)
        self.assertTrue(response.endswith(hashlib.sha256(body).hexdigest().encode()))
        self.assertEqual(self.requests, [("old", body)])

    async def test_queue_deadline_is_bounded_and_never_forwards_expired_write(self):
        self.gate.queue_timeout = 0.03
        await self.gate.pause()
        self.assertEqual(await self.post(), b"")
        await self.gate.resume(self.new)
        self.assertEqual(self.requests, [])


class DeploymentTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        (self.state / "backups").mkdir(mode=0o700)
        self.data = self.root / "data"
        self.data.mkdir(mode=0o700)
        (self.data / "blobs").mkdir()
        (self.data / "blobs" / "content").write_bytes(b"durable file")
        with database(self.data / "metadata.sqlite3") as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE entries(path TEXT, revision INTEGER);
                INSERT INTO entries VALUES('keep.txt',1);
                CREATE TABLE devices(name TEXT);
                INSERT INTO devices VALUES('fixture');
                CREATE TABLE auth_settings(key TEXT, value TEXT);
                INSERT INTO auth_settings VALUES('identity','fixture-key');
            """)
        self.docs = self.root / "cicd-site"
        for version in ("old", "new"):
            (self.docs / version).mkdir(parents=True)
            (self.docs / version / "index.html").write_text(version)
        (self.docs / "docs").symlink_to(self.docs / "old")
        deploy.write_json(self.state / "config.json", dict(
            repository="example/server", data_dir=str(self.data), docs_root=str(self.docs),
            public_url="https://sync.example.org", gateway_port=18484,
        ))
        self.old = dict(container="initial", revision="a" * 40, port=18485,
                        image_id="old-image", docs=str(self.docs / "old"))
        self.new = dict(container="mysync-cicd-candidate", revision="b" * 40, port=18486,
                        image_id="new-image", docs=str(self.docs / "new"))
        deploy.write_json(self.state / "current.json", self.old)
        self.deployment = deploy.Deployment(self.state)
        self.events = []
        self.control = mock.patch.object(self.deployment, "control", side_effect=self.command).start()
        self.stop = mock.patch.object(self.deployment, "stop", side_effect=lambda name: self.events.append(("stop", name))).start()
        self.start = mock.patch.object(self.deployment, "start", side_effect=self.start_backend).start()
        self.probe = mock.patch.object(deploy, "probe").start()
        self.addCleanup(mock.patch.stopall)

    def command(self, action, **values):
        self.events.append((action, values))
        if action == "resume" and values["port"] == self.new["port"]:
            # A request may be admitted immediately after resume; the durable
            # commit and docs must already refer to the new release.
            self.assertEqual(self.deployment.current(), self.new)
            self.assertEqual((self.docs / "docs").resolve(), self.docs / "new")

    def start_backend(self, record):
        self.events.append(("start", record["container"]))

    def mutate(self, sql):
        with database(self.data / "metadata.sqlite3") as db:
            db.execute(sql)

    def assert_restored(self):
        self.assertEqual(self.deployment.current(), self.old)
        self.assertFalse((self.state / "transaction.json").exists())
        self.assertEqual((self.data / "blobs/content").read_bytes(), b"durable file")
        with database(self.data / "metadata.sqlite3") as db:
            self.assertEqual(db.execute("SELECT * FROM entries").fetchall(), [("keep.txt", 1)])
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone(), ("ok",))
        self.assertEqual(self.events[-1], ("resume", dict(port=self.old["port"])))

    def test_success_commits_before_reopening_and_retains_recoverable_snapshot(self):
        self.deployment.switch(self.new)
        self.assertEqual(self.deployment.current(), self.new)
        self.assertEqual(deploy.read_json(self.state / "previous.json"), self.old)
        self.assertEqual(deploy.database_signature(self.data), deploy.database_signature(self.state / "backups" / self.new["container"] / "data"))
        self.assertFalse((self.state / "transaction.json").exists())

    def test_failed_start_restores_database_and_blobs_before_reopening(self):
        def start(record):
            if record == self.new:
                self.mutate("DELETE FROM entries")
                (self.data / "blobs/content").unlink()
                raise RuntimeError("candidate crashed")
        self.start.side_effect = start
        with self.assertRaisesRegex(RuntimeError, "candidate crashed"):
            self.deployment.switch(self.new)
        self.assert_restored()

    def test_schema_migration_is_rejected_and_reverted_before_serving_requests(self):
        def start(record):
            if record == self.new:
                self.mutate("ALTER TABLE entries ADD COLUMN incompatible TEXT")
        self.start.side_effect = start
        with self.assertRaisesRegex(RuntimeError, "migration requires a separate procedure"):
            self.deployment.switch(self.new)
        self.assert_restored()

    def test_identity_change_is_rejected_and_reverted(self):
        def start(record):
            if record == self.new:
                self.mutate("UPDATE auth_settings SET value='wrong identity'")
        self.start.side_effect = start
        with self.assertRaisesRegex(RuntimeError, "identity"):
            self.deployment.switch(self.new)
        self.assert_restored()

    def test_busy_transfer_aborts_without_stopping_production(self):
        self.control.side_effect = [RuntimeError("drain timed out"), {}]
        with self.assertRaisesRegex(RuntimeError, "drain timed out"):
            self.deployment.switch(self.new)
        self.assertNotIn(mock.call(self.old["container"]), self.stop.call_args_list)
        self.assertEqual(self.deployment.current(), self.old)

    def test_recovery_after_commit_never_restores_old_snapshot_over_new_writes(self):
        original = self.command
        def fail_after_commit(action, **values):
            if action == "resume" and self.deployment.current() == self.new:
                self.mutate("INSERT INTO entries VALUES('accepted-after-commit.txt',2)")
                raise KeyboardInterrupt()
            return original(action, **values)
        self.control.side_effect = fail_after_commit
        with self.assertRaises(KeyboardInterrupt):
            self.deployment.switch(self.new)
        self.control.side_effect = self.command
        self.deployment.recover()
        with database(self.data / "metadata.sqlite3") as db:
            self.assertGreater(db.execute("SELECT COUNT(*) FROM entries WHERE revision=2").fetchone()[0], 0)
        self.assertEqual(self.deployment.current(), self.new)

    def test_offline_crash_recovery_restores_old_version_without_gateway(self):
        def killed(_record):
            self.mutate("DELETE FROM entries")
            raise SystemExit(143)
        self.start.side_effect = killed
        with mock.patch.object(self.deployment, "recover"):
            with self.assertRaises(SystemExit):
                self.deployment.switch(self.new)
        self.start.side_effect = self.start_backend
        self.control.reset_mock()
        self.deployment.recover(gateway=False)
        self.control.assert_not_called()
        with database(self.data / "metadata.sqlite3") as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM entries").fetchone(), (1,))

    def test_documentation_archive_rejects_traversal_and_symlinks(self):
        for name, kind in (("../../outside", tarfile.REGTYPE), ("link", tarfile.SYMTYPE)):
            archive = self.root / "docs.tar.gz"
            with tarfile.open(archive, "w:gz") as target:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = 0
                member.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
                target.addfile(member, io.BytesIO())
            with self.assertRaisesRegex(ValueError, "unsafe"):
                self.deployment.unpack(archive, self.root / "unpacked")

    def test_busy_transfers_are_retried_automatically_without_quarantining_ci(self):
        (self.state / "activated").touch()
        revision = self.new["revision"]
        ci = dict(id=123, run_number=1, run_attempt=1, head_sha=revision,
                  head_branch="main", event="push", head_repository=dict(full_name="example/server"),
                  path=".github/workflows/ci.yml", status="completed", conclusion="success")
        with contextlib.ExitStack() as stack:
            for name, value in (("head", revision), ("gh", dict(workflow_runs=[ci])),
                                ("artifact", dict(image_id="fixture-image"))):
                stack.enter_context(mock.patch.object(self.deployment, name, return_value=value))
            for name in ("recover", "unpack", "initialize_fixture", "create"):
                stack.enter_context(mock.patch.object(self.deployment, name))
            stack.enter_context(mock.patch.object(self.deployment, "switch", side_effect=deploy.DeploymentBusy()))
            stack.enter_context(mock.patch.object(deploy, "run"))
            status = stack.enter_context(mock.patch.object(self.deployment, "status"))
            self.deployment.poll()
            self.assertEqual(status.call_args.args[1], "pending")
        self.assertFalse((self.state / "failed.json").exists())
        self.assertEqual(self.deployment.current(), self.old)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Pull successful main CI artifacts and replace a single-writer Docker service."""

import argparse
import contextlib
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile


def run(*args, timeout=30, **kwargs):
    return subprocess.run(args, check=True, timeout=timeout, **kwargs)


def output(*args, timeout=30):
    return subprocess.check_output(args, timeout=timeout, text=True).strip()


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as target:
        os.chmod(temporary, 0o600)
        json.dump(value, target, indent=2)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_json(path):
    return json.loads(path.read_text())


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def request(url, timeout=3):
    query = urllib.request.Request(url, headers={"User-Agent": "MySyncFiles-Deployment/1"})
    # Deployment checks must never silently succeed on another origin.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None
    try:
        with urllib.request.build_opener(NoRedirect).open(query, timeout=timeout) as response:
            return response.status, response.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as error:
        return error.code, error.read(4096)


def probe(port, manifest=None, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        try:
            base = f"http://127.0.0.1:{port}"
            for path, status in (("/v1/health", 200), ("/v1/server-info", 200),
                                 ("/files", 200), ("/v1/manifest", 401)):
                actual, _body = request(base + path, timeout=1)
                if actual != status:
                    raise RuntimeError(f"probe {path}: expected {status}, got {actual}")
            if manifest:
                for name, expected in manifest["web"].items():
                    path = "/" + name
                    actual, body = request(base + path, timeout=1)
                    if actual != 200 or hashlib.sha256(body).hexdigest() != expected:
                        raise RuntimeError("deployed web assets differ from the CI image")
            return
        except (OSError, RuntimeError, http.client.HTTPException):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def inspect(name):
    return json.loads(output("docker", "inspect", name))[0]


def database_signature(data):
    with contextlib.closing(sqlite3.connect(f"file:{data / 'metadata.sqlite3'}?mode=ro", uri=True)) as db:
        if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise RuntimeError("SQLite integrity check failed")
        schema = db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").fetchall()
        schema += [("user_version", db.execute("PRAGMA user_version").fetchone()[0])]
        # Expired sessions and trash can legitimately be purged at startup.
        # Durable content, identity and approved devices must remain identical.
        durable = {}
        for table in ("entries", "devices", "auth_settings"):
            rows = db.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
            durable[table] = hashlib.sha256(repr(rows).encode()).hexdigest()
        return schema, durable


class Deployment:
    def __init__(self, state):
        self.state = state.resolve()
        self.config = read_json(self.state / "config.json")
        self.repo = self.config["repository"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repo):
            raise ValueError("invalid repository")
        self.data = Path(self.config["data_dir"])
        self.docs = Path(self.config["docs_root"])

    def current(self):
        return read_json(self.state / "current.json")

    def control(self, action, **values):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(20)
            client.connect(str(self.state / "control.sock"))
            client.sendall(json.dumps(dict(action=action, **values)).encode() + b"\n")
            with client.makefile("rb") as stream:
                result = json.loads(stream.readline(4096))
            if not result["ok"]:
                raise RuntimeError(f"gateway {action} failed: {result.get('error')}")
            return result

    def gh(self, suffix):
        return json.loads(output("gh", "api", f"repos/{self.repo}/{suffix}"))

    def head(self):
        return self.gh("git/ref/heads/main")["object"]["sha"]

    def status(self, revision, status, description, run_id=None):
        # Reporting must not turn a successfully committed deployment into a rollback.
        try:
            args = ["gh", "api", "--method", "POST", f"repos/{self.repo}/statuses/{revision}",
                    "-f", f"state={status}", "-f", "context=production/deploy",
                    "-f", f"description={description[:140]}"]
            if run_id:
                args += ["-f", f"target_url=https://github.com/{self.repo}/actions/runs/{run_id}"]
            run(*args, stdout=subprocess.DEVNULL, timeout=15)
        except (subprocess.SubprocessError, OSError) as error:
            print(f"status reporting failed: {error}", flush=True)

    def create(self, image_id, name, port, data):
        run("docker", "create", "--name", name,
            "--label", "io.mysync.cicd=server", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--pids-limit", "128",
            "--memory", "512m", "--user", f"{os.getuid()}:{os.getgid()}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--mount", f"type=bind,src={data},dst=/data",
            "--publish", f"127.0.0.1:{port}:8484", "--restart", "unless-stopped",
            "--log-driver", "local", "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
            image_id, stdout=subprocess.DEVNULL)

    def initialize_fixture(self, image_id, data):
        run("docker", "run", "--rm", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--user", f"{os.getuid()}:{os.getgid()}",
            "--mount", f"type=bind,src={data},dst=/data", image_id,
            "init", "--data-dir", "/data", "--name", "Deployment validation",
            stdout=subprocess.DEVNULL)
        with contextlib.closing(sqlite3.connect(data / "metadata.sqlite3")) as db:
            db.execute("INSERT OR REPLACE INTO auth_settings VALUES('public_url', 'https://sync.example.org')")
            db.commit()

    def stop(self, name):
        run("docker", "stop", "--time", "8", name, timeout=12, stdout=subprocess.DEVNULL)

    def start(self, record):
        run("docker", "start", record["container"], timeout=10, stdout=subprocess.DEVNULL)
        probe(record["port"])

    def document_route(self, target):
        target = Path(target)
        if not target.is_relative_to(self.docs) or not (target / "index.html").is_file():
            raise RuntimeError("invalid documentation release")
        temporary = self.docs / ".docs-next"
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(target)
        os.replace(temporary, self.docs / "docs")

    def recover(self, gateway=True):
        transaction_path = self.state / "transaction.json"
        if not transaction_path.exists():
            current = self.current()
            if not inspect(current["container"])["State"]["Running"]:
                self.start(current)
            if gateway:
                self.control("resume", port=current["port"])
            return
        transaction = read_json(transaction_path)
        previous = transaction["previous"]
        candidate = transaction["candidate"]
        # current.json is the durable commit point. Once published, never restore
        # a snapshot: it could discard requests accepted after the commit.
        if self.current()["container"] == candidate["container"]:
            self.start(candidate)
            self.document_route(candidate["docs"])
            if gateway:
                self.control("resume", port=candidate["port"])
        else:
            self.stop(candidate["container"])
            if transaction["phase"] == "snapshotted":
                backup = Path(transaction["backup"])
                if not backup.is_relative_to(self.state / "backups"):
                    raise RuntimeError("invalid backup path")
                # Idempotent, including a crash between the two renames/copies.
                failed = backup / "failed-data"
                if not failed.exists():
                    os.rename(self.data, failed)
                if not self.data.exists():
                    run("cp", "-a", "--reflink=auto", str(backup / "data"), str(self.data), timeout=15)
                else:
                    # An interrupted restoration is completed before restarting.
                    run("rsync", "-a", "--delete", f"{backup / 'data'}/", f"{self.data}/", timeout=15)
                database_signature(self.data)
            self.start(previous)
            self.document_route(previous["docs"])
            if gateway:
                self.control("resume", port=previous["port"])
        transaction_path.unlink()
        print("deployment recovery complete", flush=True)

    def switch(self, candidate, manifest=None):
        previous = self.current()
        backup = self.state / "backups" / candidate["container"]
        backup.mkdir(parents=True, mode=0o700)
        transaction = dict(previous=previous, candidate=candidate,
                           backup=str(backup), phase="prepared")
        write_json(self.state / "transaction.json", transaction)
        paused_at = time.monotonic()
        try:
            self.control("pause", timeout=10)
            self.stop(previous["container"])
            # No active requests or service writer. Also exclude CLI writers while
            # copying the database, WAL and blobs as one recoverable snapshot.
            with (self.data / ".server.lock").open("a+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with contextlib.closing(sqlite3.connect(self.data / "metadata.sqlite3", timeout=2)) as db:
                    db.execute("BEGIN IMMEDIATE")
                    run("cp", "-a", "--reflink=auto", str(self.data), str(backup / "data"), timeout=10)
                    db.rollback()
            before = database_signature(backup / "data")
            transaction["phase"] = "snapshotted"
            write_json(self.state / "transaction.json", transaction)
            self.start(candidate)
            probe(candidate["port"], manifest, timeout=3)
            after = database_signature(self.data)
            if before != after:
                raise RuntimeError("schema, identity or durable content changed at startup; migration requires a separate procedure")
            if time.monotonic() - paused_at > 40:
                raise RuntimeError("switch exceeded the queue time budget")
            self.document_route(candidate["docs"])
            write_json(self.state / "previous.json", previous)
            write_json(self.state / "current.json", candidate)
            self.control("resume", port=candidate["port"])
            (self.state / "transaction.json").unlink()
            print(json.dumps(dict(event="deployed", revision=candidate["revision"],
                                  queue_seconds=round(time.monotonic() - paused_at, 3))), flush=True)
        except BaseException:
            # Includes SIGTERM converted to SystemExit by main. ExecStopPost also
            # performs this recovery after SIGKILL or an interpreter failure.
            self.recover()
            raise

    def unpack(self, archive_path, destination):
        destination.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive_path) as archive:
            members = archive.getmembers()
            if sum(member.size for member in members) > 64 * 1024 * 1024:
                raise ValueError("documentation archive is too large")
            for member in members:
                path = Path(member.name)
                if not member.isfile() or path.is_absolute() or ".." in path.parts:
                    raise ValueError("unsafe documentation archive")
            archive.extractall(destination, members=members, filter="data")
        for path in destination.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
            if path.is_file() and path.suffix in (".html", ".xml", ".js", ".json", ".txt"):
                text = path.read_text()
                path.write_text(text.replace("https://sync.example.org", self.config["public_url"]))
        destination.chmod(0o755)

    def artifact(self, run_info, revision, destination):
        artifacts = self.gh(f"actions/runs/{run_info['id']}/artifacts?per_page=100")["artifacts"]
        matches = [item for item in artifacts if item["name"] == f"server-{revision}" and not item["expired"]]
        if len(matches) != 1:
            raise RuntimeError("expected exactly one unexpired server artifact")
        artifact = matches[0]
        destination.mkdir(parents=True, mode=0o700)
        archive_path = destination / "artifact.zip"
        with archive_path.open("wb") as target:
            run("gh", "api", f"repos/{self.repo}/actions/artifacts/{artifact['id']}/zip",
                stdout=target, timeout=120)
        if artifact.get("digest") != "sha256:" + sha256(archive_path):
            raise RuntimeError("GitHub artifact digest mismatch")
        with zipfile.ZipFile(archive_path) as archive:
            if set(archive.namelist()) != {"image.tar", "docs.tar.gz", "release.json"}:
                raise RuntimeError("unexpected artifact contents")
            if sum(item.file_size for item in archive.infolist()) > 256 * 1024 * 1024:
                raise RuntimeError("artifact exceeds the size limit")
            archive.extractall(destination)
        manifest = read_json(destination / "release.json")
        if manifest["revision"] != revision or manifest["image_tag"] != f"mysyncfiles-server:git-{revision}":
            raise RuntimeError("artifact commit mismatch")
        if set(manifest["files"]) != {"image.tar", "docs.tar.gz"}:
            raise RuntimeError("invalid artifact manifest")
        if set(manifest["web"]) != {"atlas.js", "editor.js", "status.js"}:
            raise RuntimeError("invalid web manifest")
        for name, expected in manifest["files"].items():
            if sha256(destination / name) != expected:
                raise RuntimeError("artifact file checksum mismatch")
        run("docker", "load", "--input", str(destination / "image.tar"), timeout=60, stdout=subprocess.DEVNULL)
        image = json.loads(output("docker", "image", "inspect", manifest["image_tag"]))[0]
        if image["Id"] != manifest["image_id"] or image["Config"]["Labels"].get("org.opencontainers.image.revision") != revision:
            raise RuntimeError("immutable image identity mismatch")
        return manifest

    def poll(self):
        if not (self.state / "activated").exists():
            print("waiting for the one-time Nginx activation", flush=True)
            return
        self.recover()
        revision = self.head()
        if revision == self.current()["revision"]:
            return
        runs = self.gh(f"actions/workflows/ci.yml/runs?branch=main&event=push&head_sha={revision}&per_page=5")["workflow_runs"]
        runs.sort(key=lambda item: (item["run_number"], item["run_attempt"]), reverse=True)
        if not runs:
            return
        ci = runs[0]
        if (ci["head_sha"] != revision or ci["head_branch"] != "main" or ci["event"] != "push"
                or ci["head_repository"]["full_name"] != self.repo
                or ci["path"] != ".github/workflows/ci.yml"):
            raise RuntimeError("unexpected CI origin")
        if ci["conclusion"] != "success" or ci["status"] != "completed":
            return
        attempt = dict(revision=revision, run_id=ci["id"], attempt=ci["run_attempt"])
        failed_path = self.state / "failed.json"
        if failed_path.exists() and read_json(failed_path) == attempt:
            return
        self.status(revision, "pending", "Preparing the CI-tested image", ci["id"])
        try:
            with tempfile.TemporaryDirectory(prefix="artifact-", dir=self.state) as temporary:
                bundle = Path(temporary) / "bundle"
                manifest = self.artifact(ci, revision, bundle)
                docs = self.docs / "releases" / f"{revision}-{ci['id']}-{ci['run_attempt']}"
                self.unpack(bundle / "docs.tar.gz", docs)
                previous = self.current()
                port = 18486 if previous["port"] == 18485 else 18485
                smoke_data = Path(temporary) / "smoke"
                smoke_data.mkdir(mode=0o700)
                self.initialize_fixture(manifest["image_id"], smoke_data)
                name = f"mysync-cicd-{revision[:12]}-{time.time_ns()}"
                self.create(manifest["image_id"], name + "-test", port, smoke_data)
                try:
                    self.start(dict(container=name + "-test", port=port))
                    probe(port, manifest)
                finally:
                    run("docker", "rm", "--force", name + "-test", stdout=subprocess.DEVNULL)
                if self.head() != revision:
                    self.status(revision, "success", "Superseded by a newer main commit", ci["id"])
                    return
                self.create(manifest["image_id"], name, port, self.data)
                candidate = dict(revision=revision, image_id=manifest["image_id"],
                                 container=name, port=port, docs=str(docs), run_id=ci["id"])
                self.switch(candidate, manifest)
            self.check_public(manifest)
            self.status(revision, "success", "Deployed; HTTPS, identity, data and web assets verified", ci["id"])
            failed_path.unlink(missing_ok=True)
        except BaseException:
            write_json(failed_path, attempt)
            # After traffic was released, rollback uses today's live data, never
            # the pre-deployment snapshot. The unchanged schema was checked above.
            if self.current()["revision"] == revision and (self.state / "previous.json").exists():
                self.rollback()
            self.status(revision, "failure", "Deployment failed; previous version retained/restored", ci["id"])
            raise
        try:
            self.prune()
        except (OSError, subprocess.SubprocessError) as error:
            print(f"retention cleanup failed; deployed version retained: {error}", flush=True)

    def check_public(self, manifest=None):
        for path, expected in (("/v1/health", 200), ("/v1/server-info", 200),
                               ("/files", 200), ("/docs/", 200), ("/v1/manifest", 401)):
            actual, _body = request(self.config["public_url"] + path, timeout=8)
            if actual != expected:
                raise RuntimeError(f"HTTPS probe {path}: expected {expected}, got {actual}")
        if manifest:
            for name, expected in manifest["web"].items():
                actual, body = request(self.config["public_url"] + "/" + name, timeout=8)
                if actual != 200 or hashlib.sha256(body).hexdigest() != expected:
                    raise RuntimeError("HTTPS web assets differ from the deployed commit")

    def rollback(self):
        previous = read_json(self.state / "previous.json")
        self.switch(previous)
        self.status(self.current()["revision"], "success", "Previous image restored with current live data")

    def prune(self):
        # Only artifacts created by this controller; preserve current + previous.
        protected = {self.current()["container"], read_json(self.state / "previous.json")["container"]}
        backups = sorted((self.state / "backups").iterdir(), key=lambda path: path.stat().st_mtime, reverse=True)
        for backup in backups[3:]:
            if backup.name.startswith("mysync-cicd-") and backup.name not in protected:
                shutil.rmtree(backup)
        containers = output("docker", "ps", "-a", "--filter", "label=io.mysync.cicd=server", "--format", "{{.Names}}")
        for name in containers.splitlines():
            if name not in protected and not inspect(name)["State"]["Running"]:
                run("docker", "rm", name, stdout=subprocess.DEVNULL)
        records = [self.current(), read_json(self.state / "previous.json")]
        protected_docs = {Path(record["docs"]) for record in records}
        for release in (self.docs / "releases").iterdir():
            if release not in protected_docs and re.fullmatch(r"[0-9a-f]{40}-\d+-\d+", release.name):
                shutil.rmtree(release)
        protected_images = {record["image_id"] for record in records}
        images = output("docker", "images", "--filter", "reference=mysyncfiles-server:git-*", "--format", "{{.ID}} {{.Repository}}:{{.Tag}}", "--no-trunc")
        for line in images.splitlines():
            image_id, tag = line.split()
            if image_id not in protected_images:
                run("docker", "image", "rm", tag, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("command", choices=("poll", "recover", "recover-offline", "rollback", "status"))
    args = parser.parse_args()
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_args: sys.exit(143))
    with (args.state_dir / "deploy.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        deployment = Deployment(args.state_dir)
        if args.command == "status":
            print(json.dumps(dict(current=deployment.current(), gateway=deployment.control("status")), indent=2))
        elif args.command.startswith("recover"):
            deployment.recover(gateway=args.command != "recover-offline")
        else:
            getattr(deployment, args.command)()


if __name__ == "__main__":
    main()

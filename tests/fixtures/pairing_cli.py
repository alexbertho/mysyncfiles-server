"""Exercise the actual CLI on a controlling terminal, without TPM hardware."""
import os
import pty
import select
import signal
import sqlite3
import sys
import time


binary, data_dir, old_id, code = sys.argv[1:]


class Pair:
    def __enter__(self):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execl(binary, binary, "device", "pair", "--data-dir", data_dir)
        self.output = b""
        self.status = None
        return self

    def until(self, text):
        deadline = time.monotonic() + 15
        while text.encode() not in self.output:
            assert time.monotonic() < deadline, self.output.decode(errors="replace")
            ready, _, _ = select.select([self.fd], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    chunk = b""
                assert chunk, self.output.decode(errors="replace")
                self.output += chunk

    def send(self, text):
        os.write(self.fd, (text + "\n").encode())

    def finish(self, expected_success):
        deadline = time.monotonic() + 15
        while self.status is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = status
                break
            assert time.monotonic() < deadline, self.output.decode(errors="replace")
            time.sleep(0.05)
        assert (os.waitstatus_to_exitcode(self.status) == 0) == expected_success

    def __exit__(self, *exc):
        if self.status is None:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        os.close(self.fd)

    def enter_code(self):
        self.until("Device name: ")
        self.send("laptop")
        self.until("Code shown by the client: ")
        self.send(code)


with sqlite3.connect(os.path.join(data_dir, "metadata.sqlite3")) as db:
    with Pair() as pair:
        pair.enter_code()
        pair.until("Replace this pending invitation")
        pair.send("")
        pair.until("invitation unchanged")
        pair.finish(False)
    assert db.execute("SELECT expires_at>0 FROM device_enrollments WHERE id=?", (old_id,)).fetchone() == (1,)
    assert db.execute("SELECT COUNT(*) FROM device_enrollments").fetchone() == (1,)

    with Pair() as pair:
        pair.enter_code()
        pair.until("Replace this pending invitation")
        pair.send("yes")
        pair.until("Waiting for the client's TPM proof")
        new_id, = db.execute("SELECT id FROM device_enrollments WHERE id!=?", (old_id,)).fetchone()
        assert db.execute("SELECT expires_at FROM device_enrollments WHERE id=?", (old_id,)).fetchone() == (0,)
        assert db.execute("SELECT approved_at FROM device_enrollments WHERE id=?", (new_id,)).fetchone() == (None,)
        fingerprint = "a" * 64
        db.execute("UPDATE device_enrollments SET verified_at=?,fingerprint=? WHERE id=?", (int(time.time()), fingerprint, new_id))
        db.commit()
        pair.until("TPM fingerprint: " + fingerprint)
        pair.until("Approve this device? [y/N]")
        pair.send("yes")
        pair.until("Device approved.")
        pair.finish(True)
    assert db.execute("SELECT approved_at IS NOT NULL FROM device_enrollments WHERE id=?", (new_id,)).fetchone() == (1,)

    # A third attempt with another code cannot offer to replace this approval.
    code = "11111-22222-33333-44444"
    with Pair() as pair:
        pair.enter_code()
        pair.until("already enrolled")
        pair.finish(False)
        assert b"Replace this pending invitation" not in pair.output
    assert db.execute("SELECT COUNT(*) FROM device_enrollments").fetchone() == (2,)

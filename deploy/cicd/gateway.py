#!/usr/bin/env python3
"""Bounded TCP queue for an exclusive-writer service; never replay a request."""

import argparse
import asyncio
import contextlib
import json
import os
from pathlib import Path
import signal


class Gateway:
    def __init__(self, port, *, paused=False, queue_timeout=60, capacity=512):
        self.port = port
        self.paused = paused
        self.queue_timeout = queue_timeout
        self.capacity = capacity
        self.active = 0
        self.connections = 0
        self.forwarded = 0
        self.changed = asyncio.Condition()

    async def pause(self):
        async with self.changed:
            self.paused = True

    async def resume(self, port):
        if not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ValueError("invalid loopback backend port")
        async with self.changed:
            self.port = port
            self.paused = False
            self.changed.notify_all()

    async def drain(self, timeout):
        async with self.changed:
            await asyncio.wait_for(
                self.changed.wait_for(lambda: self.active == 0), timeout
            )

    async def admit(self):
        async with self.changed:
            await asyncio.wait_for(
                self.changed.wait_for(lambda: not self.paused), self.queue_timeout
            )
            # No await between reading the route and registering the connection.
            self.active += 1
            return self.port

    async def proxy(self, reader, writer):
        admitted = False
        backend = None
        pumps = []
        self.connections += 1
        try:
            if self.connections > self.capacity:
                return
            port = await self.admit()
            admitted = True
            upstream, backend = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), 3
            )
            self.forwarded += 1

            async def copy(source, target):
                while chunk := await source.read(65536):
                    target.write(chunk)
                    await target.drain()
                if target.can_write_eof():
                    target.write_eof()

            pumps = [
                asyncio.create_task(copy(reader, backend)),
                asyncio.create_task(copy(upstream, writer)),
            ]
            # HTTP Connection: close makes upstream EOF the end of the request.
            # Client half-close still permits the complete response to arrive.
            await pumps[1]
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            for task in pumps:
                task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            for stream in (backend, writer):
                if stream:
                    stream.close()
                    with contextlib.suppress(OSError):
                        await stream.wait_closed()
            async with self.changed:
                self.connections -= 1
                if admitted:
                    self.active -= 1
                self.changed.notify_all()

    async def control(self, reader, writer):
        try:
            request = json.loads(await asyncio.wait_for(reader.readline(), 5))
            action = request["action"]
            if action == "pause":
                await self.pause()
                await self.drain(min(float(request.get("timeout", 10)), 15))
            elif action == "resume":
                await self.resume(request["port"])
            elif action != "status":
                raise ValueError("unknown command")
            result = dict(ok=True, paused=self.paused, port=self.port,
                          active=self.active, connections=self.connections,
                          forwarded=self.forwarded)
        except (ValueError, KeyError, asyncio.TimeoutError) as error:
            result = dict(ok=False, error=type(error).__name__)
        try:
            writer.write(json.dumps(result).encode() + b"\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


async def serve(state):
    config = json.loads((state / "config.json").read_text())
    current = json.loads((state / "current.json").read_text())
    gate = Gateway(current["port"], paused=(state / "transaction.json").exists())
    control_path = state / "control.sock"
    control_path.unlink(missing_ok=True)
    control = await asyncio.start_unix_server(gate.control, path=control_path, limit=4096)
    os.chmod(control_path, 0o600)
    server = await asyncio.start_server(
        gate.proxy, "127.0.0.1", config["gateway_port"], backlog=512, limit=65536
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    async with control, server:
        await stop.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    asyncio.run(serve(parser.parse_args().state_dir))

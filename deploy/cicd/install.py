#!/usr/bin/env python3
"""Install the per-user controller; production remains untouched until activation."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.parse

from deploy import inspect, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--docs-root", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--public-url", required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--backend-port", type=int, default=8484)
    parser.add_argument("--gateway-port", type=int, default=18484)
    args = parser.parse_args()
    state = args.state_dir.resolve()
    for path in (state, args.data_dir, args.docs_root):
        if not path.is_absolute() or any(character.isspace() or character in '%\\\"' for character in str(path)):
            parser.error("use absolute paths without whitespace, quotes, percent or backslashes")
    origin = urllib.parse.urlsplit(args.public_url)
    if origin.scheme != "https" or not origin.netloc or origin.path not in ("", "/") or origin.query or origin.fragment or origin.username:
        parser.error("public URL must be an HTTPS origin")
    if not (args.data_dir / "metadata.sqlite3").is_file():
        parser.error("existing database not found")
    if (state / "current.json").exists():
        parser.error("already installed; preserve state and update bin/ explicitly")
    os.umask(0o077)
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    (state / "bin").mkdir(mode=0o700)
    (state / "backups").mkdir(mode=0o700)
    for source in Path(__file__).parent.glob("*.py"):
        shutil.copy2(source, state / "bin" / source.name)
    current = inspect(args.container)
    if not current["State"]["Running"]:
        parser.error("initial container must be running")
    write_json(state / "config.json", dict(
        repository=args.repository, data_dir=str(args.data_dir.resolve()),
        public_url=args.public_url.rstrip("/"), gateway_port=args.gateway_port,
        docs_root=str(args.docs_root), original_port=args.backend_port,
    ))
    write_json(state / "current.json", dict(
        revision=args.revision, image_id=current["Image"], container=args.container,
        port=args.backend_port, docs=str(args.docs_root / "bootstrap"),
    ))
    units = Path.home() / ".config/systemd/user"
    units.mkdir(parents=True, exist_ok=True)
    definitions = {
        "mysync-cicd-gateway.service": f"""[Unit]
Description=MySyncFiles persistent deployment gateway
After=network-online.target

[Service]
ExecStartPre=/usr/bin/python3 {state}/bin/deploy.py --state-dir {state} recover-offline
ExecStart=/usr/bin/python3 {state}/bin/gateway.py --state-dir {state}
Restart=on-failure
RestartSec=2
UMask=0077
NoNewPrivileges=true
MemoryMax=128M
TasksMax=64

[Install]
WantedBy=default.target
""",
        "mysync-cicd.service": f"""[Unit]
Description=MySyncFiles deploy successful main CI
Requires=mysync-cicd-gateway.service
After=mysync-cicd-gateway.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {state}/bin/deploy.py --state-dir {state} poll
ExecStopPost=/usr/bin/python3 {state}/bin/deploy.py --state-dir {state} recover
TimeoutStartSec=5min
TimeoutStopSec=55
UMask=0077
NoNewPrivileges=true
MemoryMax=512M
TasksMax=128
""",
        "mysync-cicd.timer": """[Unit]
Description=Check main CI every minute

[Timer]
OnBootSec=30s
OnUnitInactiveSec=60s
AccuracySec=5s
Unit=mysync-cicd.service

[Install]
WantedBy=timers.target
""",
    }
    for name, definition in definitions.items():
        (units / name).write_text(definition)
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "--user", "enable", "--now", "mysync-cicd-gateway.service", "mysync-cicd.timer"], check=True)
    print(json.dumps(dict(state_dir=str(state), gateway_port=args.gateway_port,
                          activation="sudo python3 " + str(state / "bin/activate.py")
                          + " --state-dir " + str(state) + " --nginx-config /etc/nginx/sites-available/INSTANCE"), indent=2))


if __name__ == "__main__":
    main()

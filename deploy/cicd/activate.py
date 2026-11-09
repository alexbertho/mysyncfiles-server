#!/usr/bin/env python3
"""One-time root step: route Nginx through the already running gateway."""

import argparse
import datetime
import os
from pathlib import Path
import shutil
import subprocess
import time

from deploy import Deployment, output, probe, read_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--nginx-config", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("this one-time Nginx change requires sudo")
    state = args.state_dir.resolve()
    config = read_json(state / "config.json")
    current = read_json(state / "current.json")
    config_path = args.nginx_config.resolve(strict=True)
    if not config_path.is_relative_to("/etc/nginx"):
        parser.error("expected a vhost file under /etc/nginx")
    probe(config["gateway_port"])
    old_text = config_path.read_text()
    old_upstream = f"proxy_pass http://127.0.0.1:{config['original_port']};"
    new_upstream = f"proxy_pass http://127.0.0.1:{config['gateway_port']};"
    docs = Path(config["docs_root"])
    if not docs.is_absolute() or docs.name != "cicd-site":
        parser.error("docs-root must be an absolute public path ending in cicd-site")
    old_root = f"root {docs.parent};"
    new_root = f"root {docs};"
    if new_upstream not in old_text:
        if old_text.count(old_upstream) != 1 or old_text.count(old_root) != 1:
            parser.error("expected exactly one application upstream and one documentation root")
        new_text = old_text.replace(old_upstream, new_upstream).replace(old_root, new_root)
        # Explicitly close backend connections so a browser keepalive never
        # prevents draining; frontend TLS connections remain persistent.
        new_text = new_text.replace(new_upstream, new_upstream + '\n        proxy_set_header Connection "close";')
    else:
        if new_root not in old_text:
            parser.error("gateway upstream exists but documentation root differs")
        new_text = old_text
    docs.mkdir(mode=0o755, exist_ok=True)
    (docs / "releases").mkdir(mode=0o755, exist_ok=True)
    if not (docs / "bootstrap").exists():
        shutil.copytree(docs.parent / "docs", docs / "bootstrap")
    if not (docs / "docs").exists():
        (docs / "docs").symlink_to("bootstrap")
    owner = state.stat()
    os.chown(docs, owner.st_uid, owner.st_gid)
    os.chown(docs / "releases", owner.st_uid, owner.st_gid)
    # Existing public docs are copied; the original docs/ directory stays intact.
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = Path("/var/backups/mysync-cicd")
    backup.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copy2(config_path, backup / f"{config_path.name}-{stamp}")
    try:
        config_path.write_text(new_text)
        subprocess.run(["nginx", "-t"], check=True, timeout=10)
        subprocess.run(["systemctl", "reload", "nginx"], check=True, timeout=10)
    except BaseException:
        config_path.write_text(old_text)
        subprocess.run(["nginx", "-t"], check=True, timeout=10)
        subprocess.run(["systemctl", "reload", "nginx"], check=True, timeout=10)
        raise
    # Old Nginx workers may still have direct connections to the old container.
    # Never authorize its replacement until those workers have finished.
    deadline = time.monotonic() + 60
    while "worker process is shutting down" in output("ps", "-C", "nginx", "-o", "args="):
        if time.monotonic() > deadline:
            raise SystemExit("old Nginx requests are still draining; rerun activation once complete")
        time.sleep(0.5)
    Deployment(state).check_public()
    with (state / "activated").open("w") as target:
        target.write(stamp + "\n")
    os.chown(state / "activated", owner.st_uid, owner.st_gid)
    print("Nginx activated; the user timer will deploy successful main CI within one minute.")


if __name__ == "__main__":
    main()

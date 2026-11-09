#!/usr/bin/env python3
"""Package the CI-tested immutable image and generic documentation."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile


def sha256(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


if __name__ == "__main__":
    revision = os.environ["GITHUB_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SystemExit("invalid commit")
    release = Path("release")
    release.mkdir()
    tag = "mysyncfiles-server:git-" + revision
    image = json.loads(subprocess.check_output(["docker", "image", "inspect", tag]))[0]
    with (release / "image.tar").open("wb") as target:
        subprocess.run(["docker", "image", "save", tag], stdout=target, check=True)
    with tarfile.open(release / "docs.tar.gz", "w:gz") as archive:
        for path in sorted(Path("site").rglob("*")):
            if path.is_file():
                archive.add(path, arcname=str(path.relative_to("site")), recursive=False)
    manifest = dict(
        revision=revision, image_id=image["Id"], image_tag=tag,
        files={name: sha256(release / name) for name in ("image.tar", "docs.tar.gz")},
        web={name: sha256(Path("web") / name) for name in ("atlas.js", "editor.js", "status.js")},
    )
    (release / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")

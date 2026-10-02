#!/usr/bin/env python3
"""Pack the panel sources into one reproducible .tar.gz (run on the deploy machine).

Usage: pack_panel.py <panel source dir> <archive.tar.gz>

Every regular file under the source directory goes in, except local state:
dotfiles and dot-directories (.env, .pytest_cache), __pycache__, compiled
Python, databases and logs. Modes are fixed (0644 files, 0755 directories),
owner root and a constant timestamp, so the archive depends on the content
only: a re-run that changes nothing extracts nothing, and modes never come from
the checkout (a Windows / WSL checkout reports 0777 for every file).
"""
from __future__ import annotations

import gzip
import io
import os
import sys
import tarfile

EXCLUDED_DIRS = {"__pycache__", "node_modules"}
EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".db", ".db-wal", ".db-shm", ".db-journal", ".sqlite", ".sqlite3", ".log")
MTIME = 946684800  # 2000-01-01T00:00:00Z


def members(src: str):
    """(archive name, source path) pairs in a stable order; path None = directory."""
    for root, dirs, files in os.walk(src):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in EXCLUDED_DIRS
                         and not os.path.islink(os.path.join(root, d)))
        rel = os.path.relpath(root, src)
        if rel != ".":
            yield rel.replace(os.sep, "/"), None
        for name in sorted(files):
            path = os.path.join(root, name)
            if name.startswith(".") or name.endswith(EXCLUDED_SUFFIXES):
                continue
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            yield os.path.normpath(os.path.join(rel, name)).replace(os.sep, "/"), path


def pack(src: str, dest: str) -> int:
    raw = io.BytesIO()
    count = 0
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for arcname, path in members(src):
            info = tarfile.TarInfo(arcname)
            info.mtime, info.uid, info.gid, info.uname, info.gname = MTIME, 0, 0, "root", "root"
            if path is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
                continue
            with open(path, "rb") as handle:
                data = handle.read()
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
            count += 1
    with open(dest, "wb") as out, gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz:
        gz.write(raw.getvalue())
    return count


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    src, dest = argv
    if not os.path.isfile(os.path.join(src, "main.py")):
        print(f"{src} does not look like the panel source (no main.py)", file=sys.stderr)
        return 1
    print(f"{pack(src, dest)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

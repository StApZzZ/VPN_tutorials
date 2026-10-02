"""Backup consistency and restore rejects traversal, corruption and links."""
import hashlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tarfile

import pytest

ROOT=Path(__file__).resolve().parents[1]


def module(name):
    path=ROOT/"deploy/ansible/roles/backup/files"/name
    loader=importlib.machinery.SourceFileLoader(name,str(path))
    spec=importlib.util.spec_from_loader(name,loader)
    result=importlib.util.module_from_spec(spec);loader.exec_module(result)
    return result


backup=module("corpvpn-backup")
restore=module("corpvpn-restore")


def archive(path,name="etc/vpn-panel/corpvpn.db",payload=b"test",link=None,bad_hash=False):
    manifest={"format":1,"public_keys":{},"files":{}}
    with tarfile.open(path,"w:gz") as tar:
        info=tarfile.TarInfo(name);info.mode=0o600
        if link:
            info.type=tarfile.SYMTYPE;info.linkname=link;tar.addfile(info)
        else:
            info.size=len(payload);tar.addfile(info,io.BytesIO(payload))
            manifest["files"][name]="bad" if bad_hash else hashlib.sha256(payload).hexdigest()
        raw=json.dumps(manifest).encode();info=tarfile.TarInfo("corpvpn-manifest.json");info.size=len(raw);tar.addfile(info,io.BytesIO(raw))


def test_restore_checks_before_touching_files(tmp_path):
    path=tmp_path/"backup.tar.gz";archive(path)
    dest=tmp_path/"host";dest.mkdir()
    restore.restore(path,dest)
    assert not (dest/"etc").exists()
    restore.restore(path,dest,True)
    file=dest/"etc/vpn-panel/corpvpn.db"
    assert file.read_bytes()==b"test" and file.stat().st_mode&0o777==0o600
    archive(path,bad_hash=True)
    with pytest.raises(ValueError,match="checksum"):restore.restore(path,dest,True)
    assert file.read_bytes()==b"test"


@pytest.mark.parametrize("name,link",[("../etc/shadow",None),("/etc/shadow",None),("etc/shadow",None),("etc/vpn-panel/link","../../../tmp/out"),("etc/vpn-panel/link","/etc/shadow")])
def test_unsafe_paths_are_rejected(tmp_path,name,link):
    path=tmp_path/"backup.tar.gz";archive(path,name,link=link)
    with pytest.raises(ValueError):restore.restore(path,tmp_path/"host",True)


def test_existing_parent_symlink_is_rejected(tmp_path):
    path=tmp_path/"backup.tar.gz";archive(path)
    root=tmp_path/"host";root.mkdir();other=tmp_path/"outside";other.mkdir();(root/"etc").symlink_to(other,target_is_directory=True)
    with pytest.raises(ValueError,match="existing symlink"):restore.restore(path,root,True)
    assert not list(other.iterdir())


def test_letsencrypt_relative_link_can_be_restored_repeatedly(tmp_path):
    path=tmp_path/"backup.tar.gz";archive(path,"etc/letsencrypt/live/vpn/fullchain.pem",link="../../archive/vpn/fullchain1.pem")
    root=tmp_path/"host";root.mkdir()
    restore.restore(path,root,True);restore.restore(path,root,True)
    link=root/"etc/letsencrypt/live/vpn/fullchain.pem"
    assert link.is_symlink() and str(link.resolve()).startswith(str(root))


def test_sqlite_online_snapshot_includes_committed_wal(tmp_path):
    live=tmp_path/"live";live.mkdir();staging=tmp_path/"staging";staging.mkdir()
    db=live/"corpvpn.db";conn=sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL");conn.execute("CREATE TABLE items(value)")
    conn.execute("INSERT INTO items VALUES('committed')");conn.commit()
    conn.execute("INSERT INTO items VALUES('uncommitted')")
    copies=backup.snapshot_databases(str(live),str(staging))
    with sqlite3.connect(copies[str(db)]) as snap:
        assert snap.execute("SELECT value FROM items").fetchall()==[("committed",)]
    conn.rollback();conn.close()

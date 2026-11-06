"""Root-owned state and credentials. Errors carry labels only."""

import json
import os
import re
import stat
import tempfile
from pathlib import Path

from .renderer import canonical, digest


class Stop(RuntimeError):
    """A safety condition prevents continuing."""


def trusted_dir(path, mode=None):
    path = Path(path)
    if not path.is_absolute():
        raise Stop("A protected directory is not absolute.")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if part in {".", ".."}:
                raise Stop("Invalid protected directory.")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise Stop("A protected directory is writable by another account.")
        if mode is not None and stat.S_IMODE(os.fstat(fd).st_mode) != mode:
            raise Stop("A protected directory has unexpected permissions.")
        return os.dup(fd)
    finally:
        os.close(fd)


def sync_dir(path):
    fd = trusted_dir(path)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def make_directory(path, mode=0o700):
    fd = trusted_dir(path.parent)
    try:
        try:
            os.mkdir(path.name, mode, dir_fd=fd)
        except FileExistsError:
            pass
        os.fsync(fd)
    finally:
        os.close(fd)
    os.close(trusted_dir(path, mode))


def read_file(path, mode=0o600, limit=2 * 1024 * 1024, parent_mode=None):
    fd = trusted_dir(path.parent, parent_mode)
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(path.name, flags, dir_fd=fd), "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != mode
            ):
                raise Stop("A protected file has unsafe type, ownership, links or permissions.")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise Stop("A protected file exceeds its size limit.")
            return data
    finally:
        os.close(fd)


def atomic_write(path, content, mode=0o600):
    fd = trusted_dir(path.parent)
    temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".ipsecvpn-", delete=False) as out:
            temp = Path(out.name)
            os.fchmod(out.fileno(), mode)
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp.name, path.name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)
        os.close(fd)


def remove_file(path):
    path.unlink(missing_ok=True)
    sync_dir(path.parent)


def write_record(path, payload):
    atomic_write(path, canonical({"payload": payload, "sha256": digest(canonical(payload))}))


def read_record(path):
    try:
        envelope = json.loads(read_file(path))
    except FileNotFoundError:
        return None
    except (ValueError, OSError):
        raise Stop("A persisted state record is unreadable.") from None
    if (
        not isinstance(envelope, dict)
        or "payload" not in envelope
        or digest(canonical(envelope["payload"])) != envelope.get("sha256")
    ):
        raise Stop("A persisted state record failed its integrity check.")
    return envelope["payload"]


def read_keys(profile):
    keys = {}
    if profile is None:
        return keys
    for link in profile["site_links"]:
        reference = link["secret_ref"]
        if not re.fullmatch(
            r"file:/etc/ipsecvpn/secrets/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", reference
        ):
            raise Stop("An IKE key reference is outside the protected directory.")
        try:
            data = read_file(Path(reference[5:]), limit=65, parent_mode=0o700).removesuffix(b"\n")
        except OSError:
            raise Stop("An IKE key is missing or cannot be opened securely.") from None
        if not re.fullmatch(rb"[0-9a-f]{64}", data) or len(set(data)) < 8:
            raise Stop("An IKE key must be a 64-character lowercase random hexadecimal value.")
        keys[link["site_id"]] = data
    if len(set(keys.values())) != len(keys):
        raise Stop("The two site links must use distinct IKE keys.")
    return keys

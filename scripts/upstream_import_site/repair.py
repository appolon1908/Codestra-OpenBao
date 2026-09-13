#!/usr/bin/env python3
"""Repair checksums inside sanitized OpenBao snapshot test archives.

The source importer intentionally neutralizes secret-shaped bytes in reviewed
upstream test fixtures.  The Raft snapshot fixture carries its own SHA256SUMS
member, so the checksum must be updated after sanitization without rewriting
member headers, order, metadata, or unrelated archive bytes.
"""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile

TARGET_SUFFIX = "upstream/physical/raft/snapshot/testdata/spaces-meta.tar"
_STATE_NAME = "state.bin"
_SUMS_NAME = "SHA256SUMS"
_SUM_LINE = re.compile(
    rb"(?m)^(?P<digest>[0-9a-f]{64})(?P<suffix>[ \t]+\*?(?:\./)?state\.bin\r?)$"
)


def _member_signature(member: tarfile.TarInfo) -> tuple[object, ...]:
    return (
        member.name,
        member.size,
        member.mode,
        member.uid,
        member.gid,
        member.mtime,
        member.type,
        member.linkname,
        member.uname,
        member.gname,
        member.devmajor,
        member.devminor,
        tuple(sorted(member.pax_headers.items())),
    )


def _single_member(members: list[tarfile.TarInfo], basename: str) -> tarfile.TarInfo:
    matches = [member for member in members if Path(member.name).name == basename]
    if len(matches) != 1 or not matches[0].isfile():
        raise RuntimeError(
            f"expected exactly one regular {basename} member, found {len(matches)}"
        )
    return matches[0]


def _read_archive(raw: bytes) -> tuple[
    list[tuple[object, ...]], tarfile.TarInfo, bytes, tarfile.TarInfo, bytes
]:
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        state_member = _single_member(members, _STATE_NAME)
        sums_member = _single_member(members, _SUMS_NAME)
        state_stream = archive.extractfile(state_member)
        sums_stream = archive.extractfile(sums_member)
        if state_stream is None or sums_stream is None:
            raise RuntimeError("unable to read required snapshot archive members")
        return (
            [_member_signature(member) for member in members],
            state_member,
            state_stream.read(),
            sums_member,
            sums_stream.read(),
        )


def repair_known_archive(path: str | os.PathLike[str]) -> bool:
    """Repair the embedded state.bin checksum in-place and verify invariants.

    Returns ``True`` when bytes changed and ``False`` when the archive was
    already correct.  The replacement is fixed-width, so the tar length and
    every byte outside the SHA256SUMS data payload remain unchanged.
    """

    archive_path = Path(path)
    if not archive_path.as_posix().endswith(TARGET_SUFFIX):
        raise RuntimeError(f"unsupported archive repair target: {archive_path}")

    original = archive_path.read_bytes()
    (
        original_members,
        _state_member,
        state_bytes,
        sums_member,
        sums_bytes,
    ) = _read_archive(original)

    if sums_member.size != len(sums_bytes):
        raise RuntimeError("SHA256SUMS member size/read mismatch")
    matches = list(_SUM_LINE.finditer(sums_bytes))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one state.bin checksum entry, found {len(matches)}"
        )

    expected_digest = hashlib.sha256(state_bytes).hexdigest().encode("ascii")
    match = matches[0]
    current_digest = match.group("digest")
    if current_digest == expected_digest:
        print(
            "OPENBAO_SANITIZED_SNAPSHOT_CHECKSUM=PASS "
            f"archive={archive_path.as_posix()} state_sha256={expected_digest.decode()}"
        )
        return False

    repaired_sums = bytearray(sums_bytes)
    repaired_sums[match.start("digest") : match.end("digest")] = expected_digest
    if len(repaired_sums) != len(sums_bytes):
        raise RuntimeError("checksum repair changed SHA256SUMS member length")

    start = sums_member.offset_data
    end = start + sums_member.size
    if end > len(original):
        raise RuntimeError("SHA256SUMS member extends beyond archive")
    repaired = bytearray(original)
    repaired[start:end] = repaired_sums

    mode = stat.S_IMODE(archive_path.stat().st_mode)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{archive_path.name}.", suffix=".repair", dir=archive_path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as stream:
            stream.write(repaired)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, archive_path)
    finally:
        temporary_path.unlink(missing_ok=True)

    final = archive_path.read_bytes()
    (
        final_members,
        _final_state_member,
        final_state_bytes,
        final_sums_member,
        final_sums_bytes,
    ) = _read_archive(final)

    if len(final) != len(original):
        raise RuntimeError("archive length changed during checksum repair")
    if final_members != original_members:
        raise RuntimeError("archive member order or metadata changed during repair")
    if final_state_bytes != state_bytes:
        raise RuntimeError("state.bin changed during checksum repair")
    if final_sums_member.offset_data != sums_member.offset_data:
        raise RuntimeError("SHA256SUMS member offset changed during repair")
    if original[:start] != final[:start] or original[end:] != final[end:]:
        raise RuntimeError("bytes outside SHA256SUMS payload changed during repair")

    final_matches = list(_SUM_LINE.finditer(final_sums_bytes))
    if len(final_matches) != 1 or final_matches[0].group("digest") != expected_digest:
        raise RuntimeError("repaired archive does not validate state.bin checksum")

    print(
        "OPENBAO_SANITIZED_SNAPSHOT_CHECKSUM=REPAIRED "
        f"archive={archive_path.as_posix()} state_sha256={expected_digest.decode()}"
    )
    return True


if __name__ == "__main__":
    repair_known_archive(Path(TARGET_SUFFIX))

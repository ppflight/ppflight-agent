#!/usr/bin/env python3
"""Remove legacy fixed timezones from PPFlight-managed PVE template vendor-data.

The original content-addressed snippet is never edited or deleted.  A sanitized
content-addressed successor is written on the same snippets storage and each
validated PPFlight template is switched with ``qm set --cicustom``.  The script
fails closed before mutation when any managed reference is ambiguous or has a
hash mismatch, and rolls back earlier config switches if a later switch fails.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Optional


CONFIG_DIR = Path("/etc/pve/qemu-server")
MAX_CONFIG_BYTES = 1 << 20
MAX_SNIPPET_BYTES = 1 << 20
VENDOR_RE = re.compile(
    r"^(?P<storage>[A-Za-z][A-Za-z0-9_.-]*):snippets/"
    r"(?P<prefix>ppflight-(?:debian|rpm)-)(?P<digest>[a-f0-9]{64})\.yaml$"
)
TIMEZONE_RE = re.compile(r"^timezone:[ \t]+[^#\r\n]+(?:[ \t]+#.*)?(?:\r?\n)?$")


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Migration:
    vmid: int
    old_cicustom: str
    new_cicustom: str
    new_volume: str
    new_path: Path
    new_content: bytes


def run(*argv: str) -> str:
    completed = subprocess.run(
        argv,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "command failed"
        raise MigrationError(f"{' '.join(argv[:2])}: {message}")
    return completed.stdout


def read_limited(path: Path, limit: int, label: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise MigrationError(f"{label} is not a safe regular file: {path}")
        data = os.read(descriptor, limit + 1)
    except OSError as error:
        raise MigrationError(f"cannot read {label} {path}: {error}") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if len(data) > limit:
        raise MigrationError(f"{label} is too large: {path}")
    return data


def config_value(raw: str, key: str) -> Optional[str]:
    values = [line[len(key) + 2 :].strip() for line in raw.splitlines() if line.startswith(f"{key}: ")]
    if len(values) > 1:
        raise MigrationError(f"duplicate {key} property")
    return values[0] if values else None


def sanitized_vendor(content: bytes) -> Optional[bytes]:
    try:
        lines = content.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as error:
        raise MigrationError("managed vendor-data is not UTF-8") from error
    matches = [index for index, line in enumerate(lines) if TIMEZONE_RE.fullmatch(line)]
    if not matches:
        return None
    if len(matches) != 1:
        raise MigrationError("managed vendor-data has multiple top-level timezone properties")
    del lines[matches[0]]
    result = "".join(lines).encode("utf-8")
    if not result.startswith(b"#cloud-config"):
        raise MigrationError("managed vendor-data has no cloud-config header")
    return result


def replace_vendor(cicustom: str, old_volume: str, new_volume: str) -> str:
    parts = cicustom.split(",")
    matches = [index for index, part in enumerate(parts) if part == f"vendor={old_volume}"]
    if len(matches) != 1:
        raise MigrationError("managed cicustom has an ambiguous vendor component")
    parts[matches[0]] = f"vendor={new_volume}"
    return ",".join(parts)


def resolve_volume(volume: str) -> Path:
    output = run("pvesm", "path", volume).strip()
    if not output.startswith("/") or "\n" in output:
        raise MigrationError(f"PVE returned an invalid snippets path for {volume}")
    return Path(output)


def plan_migrations() -> tuple[list[Migration], int]:
    if not CONFIG_DIR.is_dir():
        raise MigrationError(f"PVE QEMU config directory is missing: {CONFIG_DIR}")
    migrations: list[Migration] = []
    scanned = 0
    for config_path in sorted(CONFIG_DIR.glob("*.conf")):
        if not config_path.stem.isdigit():
            continue
        raw = read_limited(config_path, MAX_CONFIG_BYTES, "QEMU config").decode("utf-8")
        if config_value(raw, "template") != "1":
            continue
        cicustom = config_value(raw, "cicustom")
        if not cicustom:
            continue
        vendor_components = [part[len("vendor=") :] for part in cicustom.split(",") if part.startswith("vendor=")]
        managed_components = [volume for volume in vendor_components if VENDOR_RE.fullmatch(volume)]
        if not managed_components:
            continue
        if len(vendor_components) != 1 or len(managed_components) != 1:
            raise MigrationError(f"managed cicustom is ambiguous for VMID {config_path.stem}")
        old_volume = managed_components[0]
        match = VENDOR_RE.fullmatch(old_volume)
        if not match:
            continue
        scanned += 1
        source_path = resolve_volume(old_volume)
        source_content = read_limited(source_path, MAX_SNIPPET_BYTES, "managed vendor-data")
        observed_digest = hashlib.sha256(source_content).hexdigest()
        if observed_digest != match.group("digest"):
            raise MigrationError(f"managed vendor-data hash mismatch for VMID {config_path.stem}")
        new_content = sanitized_vendor(source_content)
        if new_content is None:
            continue
        new_digest = hashlib.sha256(new_content).hexdigest()
        new_name = f"{match.group('prefix')}{new_digest}.yaml"
        new_volume = f"{match.group('storage')}:snippets/{new_name}"
        new_path = source_path.with_name(new_name)
        migrations.append(
            Migration(
                vmid=int(config_path.stem),
                old_cicustom=cicustom,
                new_cicustom=replace_vendor(cicustom, old_volume, new_volume),
                new_volume=new_volume,
                new_path=new_path,
                new_content=new_content,
            )
        )
    return migrations, scanned


def install_snippet(migration: Migration) -> None:
    path = migration.new_path
    if path.exists() or path.is_symlink():
        existing = read_limited(path, MAX_SNIPPET_BYTES, "sanitized vendor-data")
        if existing != migration.new_content:
            raise MigrationError(f"sanitized vendor-data path has different content: {path}")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o644)
        os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(migration.new_content)
            output.flush()
            os.fsync(output.fileno())
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError:
        existing = read_limited(path, MAX_SNIPPET_BYTES, "sanitized vendor-data")
        if existing != migration.new_content:
            raise MigrationError(f"sanitized vendor-data raced with different content: {path}")
    finally:
        if descriptor != -1:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def verify_template(migration: Migration, expected: str) -> None:
    raw = run("qm", "config", str(migration.vmid))
    if config_value(raw, "template") != "1" or config_value(raw, "cicustom") != expected:
        raise MigrationError(f"VMID {migration.vmid} did not retain the expected template cicustom")


def apply_migrations(migrations: list[Migration]) -> None:
    for migration in migrations:
        install_snippet(migration)
    applied: list[Migration] = []
    try:
        for migration in migrations:
            run("qm", "set", str(migration.vmid), "--cicustom", migration.new_cicustom)
            verify_template(migration, migration.new_cicustom)
            applied.append(migration)
    except Exception as error:
        rollback_errors: list[str] = []
        for migration in reversed(applied):
            try:
                run("qm", "set", str(migration.vmid), "--cicustom", migration.old_cicustom)
                verify_template(migration, migration.old_cicustom)
            except Exception as rollback_error:  # pragma: no cover - catastrophic host failure
                rollback_errors.append(str(rollback_error))
        suffix = f"; rollback failed: {'; '.join(rollback_errors)}" if rollback_errors else "; prior template switches rolled back"
        raise MigrationError(f"template migration failed: {error}{suffix}") from error


def main() -> int:
    if os.geteuid() != 0:
        raise MigrationError("run as root on the target PVE host")
    migrations, scanned = plan_migrations()
    apply_migrations(migrations)
    print(
        "PPFlight legacy template timezone migration: "
        f"scanned={scanned} migrated={len(migrations)} unchanged={scanned - len(migrations)}"
    )
    for migration in migrations:
        print(f"migrated PPFlight template VMID {migration.vmid} to {migration.new_volume}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MigrationError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)

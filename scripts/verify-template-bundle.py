#!/usr/bin/env python3
"""Strict verifier used before installing the vendored template bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional


MANIFEST = "agent-vendor-manifest.v1.json"
SCHEMA = "ppflight.agent-vendor-manifest/v1"
MAX_FILE_BYTES = 4 << 20
DIGEST = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
REVISION = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[1-9][0-9]*$")
PATH_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,255}$")
PVE_CONFIG_DIR = Path("/etc/pve/qemu-server")
PVE_MAX_CONFIG_BYTES = 1 << 20
PVE_MAX_SNIPPET_BYTES = 1 << 20
PVE_VENDOR = re.compile(
    r"^(?P<storage>[A-Za-z][A-Za-z0-9_.-]*):snippets/"
    r"(?P<prefix>ppflight-(?:debian|rpm)-)(?P<digest>[a-f0-9]{64})\.yaml$"
)
PVE_TIMEZONE = re.compile(r"^timezone:[ \t]+[^#\r\n]+(?:[ \t]+#.*)?(?:\r?\n)?$")


class InvalidBundle(Exception):
    pass


class TemplateMigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class TemplateMigration:
    vmid: int
    old_cicustom: str
    new_cicustom: str
    new_volume: str
    new_path: Path
    new_content: bytes


def pve_run(*argv: str) -> str:
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
        raise TemplateMigrationError(f"{' '.join(argv[:2])}: {message}")
    return completed.stdout


def pve_read_limited(path: Path, limit: int, label: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise TemplateMigrationError(f"{label} is not a safe regular file: {path}")
        data = os.read(descriptor, limit + 1)
    except OSError as error:
        raise TemplateMigrationError(f"cannot read {label} {path}: {error}") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if len(data) > limit:
        raise TemplateMigrationError(f"{label} is too large: {path}")
    return data


def pve_config_value(raw: str, key: str) -> Optional[str]:
    values = [line[len(key) + 2 :].strip() for line in raw.splitlines() if line.startswith(f"{key}: ")]
    if len(values) > 1:
        raise TemplateMigrationError(f"duplicate {key} property")
    return values[0] if values else None


def pve_sanitized_vendor(content: bytes) -> Optional[bytes]:
    try:
        lines = content.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as error:
        raise TemplateMigrationError("managed vendor-data is not UTF-8") from error
    matches = [index for index, line in enumerate(lines) if PVE_TIMEZONE.fullmatch(line)]
    if not matches:
        return None
    if len(matches) != 1:
        raise TemplateMigrationError("managed vendor-data has multiple top-level timezone properties")
    del lines[matches[0]]
    result = "".join(lines).encode("utf-8")
    if not result.startswith(b"#cloud-config"):
        raise TemplateMigrationError("managed vendor-data has no cloud-config header")
    return result


def pve_replace_vendor(cicustom: str, old_volume: str, new_volume: str) -> str:
    parts = cicustom.split(",")
    matches = [index for index, part in enumerate(parts) if part == f"vendor={old_volume}"]
    if len(matches) != 1:
        raise TemplateMigrationError("managed cicustom has an ambiguous vendor component")
    parts[matches[0]] = f"vendor={new_volume}"
    return ",".join(parts)


def pve_resolve_volume(volume: str) -> Path:
    output = pve_run("pvesm", "path", volume).strip()
    if not output.startswith("/") or "\n" in output:
        raise TemplateMigrationError(f"PVE returned an invalid snippets path for {volume}")
    return Path(output)


def pve_plan_template_migrations() -> tuple[list[TemplateMigration], int]:
    if not PVE_CONFIG_DIR.is_dir():
        raise TemplateMigrationError(f"PVE QEMU config directory is missing: {PVE_CONFIG_DIR}")
    migrations: list[TemplateMigration] = []
    scanned = 0
    for config_path in sorted(PVE_CONFIG_DIR.glob("*.conf")):
        if not config_path.stem.isdigit():
            continue
        try:
            raw = pve_read_limited(config_path, PVE_MAX_CONFIG_BYTES, "QEMU config").decode("utf-8")
        except UnicodeDecodeError as error:
            raise TemplateMigrationError(f"QEMU config is not UTF-8: {config_path}") from error
        if pve_config_value(raw, "template") != "1":
            continue
        cicustom = pve_config_value(raw, "cicustom")
        if not cicustom:
            continue
        vendor_components = [part[len("vendor=") :] for part in cicustom.split(",") if part.startswith("vendor=")]
        managed_components = [volume for volume in vendor_components if PVE_VENDOR.fullmatch(volume)]
        if not managed_components:
            continue
        if len(vendor_components) != 1 or len(managed_components) != 1:
            raise TemplateMigrationError(f"managed cicustom is ambiguous for VMID {config_path.stem}")
        old_volume = managed_components[0]
        match = PVE_VENDOR.fullmatch(old_volume)
        assert match is not None
        scanned += 1
        source_path = pve_resolve_volume(old_volume)
        source_content = pve_read_limited(source_path, PVE_MAX_SNIPPET_BYTES, "managed vendor-data")
        observed_digest = hashlib.sha256(source_content).hexdigest()
        if observed_digest != match.group("digest"):
            raise TemplateMigrationError(f"managed vendor-data hash mismatch for VMID {config_path.stem}")
        new_content = pve_sanitized_vendor(source_content)
        if new_content is None:
            continue
        new_digest = hashlib.sha256(new_content).hexdigest()
        new_name = f"{match.group('prefix')}{new_digest}.yaml"
        new_volume = f"{match.group('storage')}:snippets/{new_name}"
        migrations.append(
            TemplateMigration(
                vmid=int(config_path.stem),
                old_cicustom=cicustom,
                new_cicustom=pve_replace_vendor(cicustom, old_volume, new_volume),
                new_volume=new_volume,
                new_path=source_path.with_name(new_name),
                new_content=new_content,
            )
        )
    return migrations, scanned


def pve_install_snippet(migration: TemplateMigration) -> None:
    path = migration.new_path
    if path.exists() or path.is_symlink():
        existing = pve_read_limited(path, PVE_MAX_SNIPPET_BYTES, "sanitized vendor-data")
        if existing != migration.new_content:
            raise TemplateMigrationError(f"sanitized vendor-data path has different content: {path}")
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
        existing = pve_read_limited(path, PVE_MAX_SNIPPET_BYTES, "sanitized vendor-data")
        if existing != migration.new_content:
            raise TemplateMigrationError(f"sanitized vendor-data raced with different content: {path}")
    finally:
        if descriptor != -1:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def pve_verify_template(migration: TemplateMigration, expected: str) -> None:
    raw = pve_run("qm", "config", str(migration.vmid))
    if pve_config_value(raw, "template") != "1" or pve_config_value(raw, "cicustom") != expected:
        raise TemplateMigrationError(f"VMID {migration.vmid} did not retain the expected template cicustom")


def pve_apply_template_migrations(migrations: list[TemplateMigration]) -> None:
    for migration in migrations:
        pve_install_snippet(migration)
    applied: list[TemplateMigration] = []
    try:
        for migration in migrations:
            pve_run("qm", "set", str(migration.vmid), "--cicustom", migration.new_cicustom)
            applied.append(migration)
            pve_verify_template(migration, migration.new_cicustom)
    except Exception as error:
        rollback_errors: list[str] = []
        for migration in reversed(applied):
            try:
                pve_run("qm", "set", str(migration.vmid), "--cicustom", migration.old_cicustom)
                pve_verify_template(migration, migration.old_cicustom)
            except Exception as rollback_error:  # pragma: no cover - catastrophic host failure
                rollback_errors.append(str(rollback_error))
        suffix = f"; rollback failed: {'; '.join(rollback_errors)}" if rollback_errors else "; prior template switches rolled back"
        raise TemplateMigrationError(f"template migration failed: {error}{suffix}") from error


def migrate_legacy_template_timezones() -> int:
    if os.geteuid() != 0:
        raise TemplateMigrationError("run as root on the target PVE host")
    migrations, scanned = pve_plan_template_migrations()
    pve_apply_template_migrations(migrations)
    print(
        "PPFlight legacy template timezone migration: "
        f"scanned={scanned} migrated={len(migrations)} unchanged={scanned - len(migrations)}"
    )
    for migration in migrations:
        print(f"migrated PPFlight template VMID {migration.vmid} to {migration.new_volume}")
    return 0


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidBundle("manifest contains a duplicate JSON key")
        result[key] = value
    return result


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise InvalidBundle(f"{label} keys are invalid")
    return value


def protected(path: Path, want_directory: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InvalidBundle("bundle contains a missing path") from exc
    if stat.S_ISLNK(info.st_mode):
        raise InvalidBundle("bundle contains a symbolic link")
    if want_directory and not stat.S_ISDIR(info.st_mode):
        raise InvalidBundle("bundle path parent is not a directory")
    if not want_directory and not stat.S_ISREG(info.st_mode):
        raise InvalidBundle("bundle path is not a regular file")
    if os.name != "nt" and info.st_mode & 0o022:
        raise InvalidBundle("bundle path is group/world writable")
    return info


def safe_file(root: Path, relative: str) -> tuple[Path, os.stat_result]:
    if not PATH_VALUE.fullmatch(relative) or "\\" in relative:
        raise InvalidBundle("manifest file path is invalid")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise InvalidBundle("manifest file path escapes the bundle")
    current = root
    for part in pure.parts[:-1]:
        current /= part
        protected(current, True)
    target = current / pure.parts[-1]
    return target, protected(target, False)


def sha256_file(path: Path, expected_info: os.stat_result) -> str:
    if expected_info.st_size < 1 or expected_info.st_size > MAX_FILE_BYTES:
        raise InvalidBundle("bundle file size is invalid")
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        actual_info = os.fstat(descriptor)
        if (actual_info.st_dev, actual_info.st_ino) != (expected_info.st_dev, expected_info.st_ino):
            raise InvalidBundle("bundle file changed during verification")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while chunk := handle.read(128 << 10):
                digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def load_bundle(root_value: str) -> tuple[dict[str, object], list[str], str]:
    root = Path(root_value)
    if not root.is_absolute():
        root = Path.cwd() / root
    root = Path(os.path.abspath(root))
    protected(root, True)
    manifest_path, manifest_info = safe_file(root, MANIFEST)
    if manifest_info.st_size < 2 or manifest_info.st_size > 1 << 20:
        raise InvalidBundle("manifest size is invalid")
    try:
        raw = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(raw, object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InvalidBundle("manifest is not strict UTF-8 JSON") from exc
    manifest = exact_keys(
        manifest,
        {
            "schemaVersion",
            "bundleVersion",
            "catalogRevision",
            "catalogSha256",
            "entrypoint",
            "files",
            "dependencies",
            "networkHosts",
            "networkRedirectPolicy",
        },
        "manifest",
    )
    version = manifest["bundleVersion"]
    revision = manifest["catalogRevision"]
    catalog_digest = manifest["catalogSha256"]
    if (
        manifest["schemaVersion"] != SCHEMA
        or not isinstance(version, str)
        or not VERSION.fullmatch(version)
        or not isinstance(revision, str)
        or not REVISION.fullmatch(revision)
        or not isinstance(catalog_digest, str)
        or not DIGEST.fullmatch(catalog_digest)
        or manifest["entrypoint"] != "tools/ppflight-template-bootstrap.py"
    ):
        raise InvalidBundle("manifest identity is invalid")
    dependencies = exact_keys(manifest["dependencies"], {"python", "bash", "commands", "perlModules"}, "dependencies")
    if dependencies["python"] != ">=3.9" or dependencies["bash"] != ">=5":
        raise InvalidBundle("dependency versions are invalid")
    for key in ("commands", "perlModules"):
        values = dependencies[key]
        if not isinstance(values, list) or not values or any(not isinstance(item, str) or not item for item in values) or len(set(values)) != len(values):
            raise InvalidBundle(f"dependency {key} is invalid")
    hosts = manifest["networkHosts"]
    if not isinstance(hosts, list) or not hosts or any(not isinstance(host, str) or len(host) > 253 for host in hosts) or len(set(hosts)) != len(hosts):
        raise InvalidBundle("network host allowlist is invalid")
    redirect_policy = exact_keys(
        manifest["networkRedirectPolicy"],
        {"allowed", "schemes", "addressFamily", "hostPolicy", "integrityPolicy"},
        "networkRedirectPolicy",
    )
    if redirect_policy != {
        "allowed": True,
        "schemes": ["https"],
        "addressFamily": "ipv4-only",
        "hostPolicy": "upstream-selected",
        "integrityPolicy": "catalog-sha256-and-official-checksum",
    }:
        raise InvalidBundle("network redirect policy is invalid")
    files = manifest["files"]
    if not isinstance(files, list) or not 3 <= len(files) <= 32:
        raise InvalidBundle("manifest file list is invalid")
    paths: list[str] = []
    entrypoint_found = False
    catalog_found = False
    for item_value in files:
        item = exact_keys(item_value, {"path", "sha256", "requiredAtRuntime"}, "file")
        relative = item["path"]
        expected = item["sha256"]
        required = item["requiredAtRuntime"]
        if not isinstance(relative, str) or relative in paths or not isinstance(expected, str) or not DIGEST.fullmatch(expected) or not isinstance(required, bool):
            raise InvalidBundle("manifest file entry is invalid")
        path, info = safe_file(root, relative)
        if sha256_file(path, info) != expected:
            raise InvalidBundle("bundle file SHA-256 mismatch")
        paths.append(relative)
        entrypoint_found |= relative == manifest["entrypoint"] and required
        catalog_found |= relative == "catalog/template-catalog.v1.json" and required and expected == catalog_digest
    if not entrypoint_found or not catalog_found:
        raise InvalidBundle("required runtime files are incomplete")
    # Include the manifest bytes, not only the catalog digest: helper/schema
    # hardening with an unchanged catalog must still install as a new immutable
    # version directory.
    manifest_digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    bundle_id = f"{version}-{revision}-{manifest_digest[:16]}"
    return manifest, paths, bundle_id


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("verify", "bundle-id", "list", "commands", "perl-modules", "migrate-legacy-timezones"))
    parser.add_argument("root", nargs="?")
    arguments = parser.parse_args()
    if arguments.mode == "migrate-legacy-timezones":
        if arguments.root is not None:
            parser.error("migrate-legacy-timezones does not accept a bundle root")
        return migrate_legacy_template_timezones()
    if arguments.root is None:
        parser.error("the bundle root is required")
    manifest, paths, bundle_id = load_bundle(arguments.root)
    if arguments.mode == "bundle-id":
        print(bundle_id)
    elif arguments.mode == "list":
        for path in paths:
            print(path)
    elif arguments.mode == "commands":
        for command in manifest["dependencies"]["commands"]:
            print(command)
    elif arguments.mode == "perl-modules":
        for module in manifest["dependencies"]["perlModules"]:
            print(module)
    else:
        print(json.dumps({"bundleId": bundle_id, "fileCount": len(paths)}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InvalidBundle as exc:
        print(f"invalid template bundle: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except TemplateMigrationError as exc:
        print(f"template migration failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

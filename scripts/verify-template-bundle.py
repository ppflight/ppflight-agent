#!/usr/bin/env python3
"""Strict verifier used before installing the vendored template bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath


MANIFEST = "agent-vendor-manifest.v1.json"
SCHEMA = "ppflight.agent-vendor-manifest/v1"
MAX_FILE_BYTES = 4 << 20
DIGEST = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
REVISION = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[1-9][0-9]*$")
PATH_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,255}$")


class InvalidBundle(Exception):
    pass


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
    parser.add_argument("mode", choices=("verify", "bundle-id", "list", "commands", "perl-modules"))
    parser.add_argument("root")
    arguments = parser.parse_args()
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

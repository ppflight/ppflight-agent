#!/usr/bin/env python3
"""Strict local orchestration contract for PPFlight PVE template bootstrap.

The public CLI never accepts a catalog path, a download URL, or a replacement
flag.  All PVE commands are invoked as argv arrays with ``shell=False``.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit


CATALOG_SCHEMA = "ppflight.template-catalog/v1"
REQUEST_SCHEMA = "ppflight.template-bootstrap-request/v1"
RESULT_SCHEMA = "ppflight.template-bootstrap-result/v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "catalog" / "template-catalog.v1.json"
BUILDER_PATH = REPO_ROOT / "build-cloud-templates.sh"

STORAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PVE_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
BRIDGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
SAFE_KEY_RE = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
REVISION_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[1-9][0-9]*$")
VERSION_RE = re.compile(r"^[0-9]+(?:[.-][a-z0-9]+)*$")
RFC3339_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$")
HEX_RE = re.compile(r"^[0-9a-f]+$")
UPID_RE = re.compile(r"^UPID:[A-Za-z0-9:._@!-]{1,500}$")
CONTENT_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
TEST_NET = ipaddress.ip_network("192.0.2.0/24")
ALLOWED_SOURCE_HOSTS = {
    "cloud-images.ubuntu.com",
    "repo.almalinux.org",
    "cloud.debian.org",
    "cloud.centos.org",
}
FILE_CONTENT_STORAGE_TYPES = {"btrfs", "cephfs", "cifs", "dir", "glusterfs", "nfs"}
BUILDER_SETTING_KEYS = {
    "CONFIG_FILE",
    "IMAGE_STORAGE",
    "FILE_STORAGE",
    "BACKUP_STORAGE",
    "BRIDGE",
    "CACHE_DIR",
    "DISK_SIZE",
    "MEMORY_MB",
    "CORES",
    "CPU_TYPE",
    "BALLOON",
    "FIREWALL",
    "DISK_SSD",
    "DNS_SERVERS",
    "TIMEZONE",
    "ALLOW_ROOT_PASSWORD_SSH",
    "ENABLE_QOS",
    "REPLACE_EXISTING",
    "FORCE_REPLACE_UNMANAGED",
    "CLEANUP_FAILED_VM",
    "ONLY_TEMPLATES",
    "EXPECTED_CATALOG_REVISION",
    "EXPECTED_CATALOG_SHA256",
    "QOS_MBPS_RD",
    "QOS_MBPS_WR",
    "QOS_MBPS_RD_MAX",
    "QOS_MBPS_WR_MAX",
    "QOS_IOPS_RD",
    "QOS_IOPS_WR",
    "QOS_IOPS_RD_MAX",
    "QOS_IOPS_WR_MAX",
    "QOS_IOPS_RD_MAX_LENGTH",
    "QOS_IOPS_WR_MAX_LENGTH",
}

# urlKey is the only bridge from the public catalog to the network.  There is
# deliberately no CLI or environment override for any source URL.
URL_SPECS: Mapping[str, Mapping[str, str]] = {
    "ubuntu-jammy-release-amd64": {
        "filename": "ubuntu-22.04-server-cloudimg-amd64.img",
        "url": "https://cloud-images.ubuntu.com/releases/jammy/release-20260826/ubuntu-22.04-server-cloudimg-amd64.img",
        "checksumUrl": "https://cloud-images.ubuntu.com/releases/jammy/release-20260826/SHA256SUMS",
        "checksumAlgorithm": "sha256",
    },
    "ubuntu-noble-release-amd64": {
        "filename": "ubuntu-24.04-server-cloudimg-amd64.img",
        "url": "https://cloud-images.ubuntu.com/releases/noble/release-20260826/ubuntu-24.04-server-cloudimg-amd64.img",
        "checksumUrl": "https://cloud-images.ubuntu.com/releases/noble/release-20260826/SHA256SUMS",
        "checksumAlgorithm": "sha256",
    },
    "almalinux-8-genericcloud-amd64": {
        "filename": "AlmaLinux-8-GenericCloud-8.10-20260831.x86_64.qcow2",
        "url": "https://repo.almalinux.org/almalinux/8/cloud/x86_64/images/AlmaLinux-8-GenericCloud-8.10-20260831.x86_64.qcow2",
        "checksumUrl": "https://repo.almalinux.org/almalinux/8/cloud/x86_64/images/CHECKSUM",
        "checksumAlgorithm": "sha256",
    },
    "debian-13-generic-amd64": {
        "filename": "debian-13-generic-amd64-20260831-2587.qcow2",
        "url": "https://cloud.debian.org/images/cloud/trixie/20260831-2587/debian-13-generic-amd64-20260831-2587.qcow2",
        "checksumUrl": "https://cloud.debian.org/images/cloud/trixie/20260831-2587/SHA512SUMS",
        "checksumAlgorithm": "sha512",
    },
    "debian-12-generic-amd64": {
        "filename": "debian-12-generic-amd64-20260821-2577.qcow2",
        "url": "https://cloud.debian.org/images/cloud/bookworm/20260821-2577/debian-12-generic-amd64-20260821-2577.qcow2",
        "checksumUrl": "https://cloud.debian.org/images/cloud/bookworm/20260821-2577/SHA512SUMS",
        "checksumAlgorithm": "sha512",
    },
    "centos-stream-9-genericcloud-amd64": {
        "filename": "CentOS-Stream-GenericCloud-9-20260901.0.x86_64.qcow2",
        "url": "https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-20260901.0.x86_64.qcow2",
        "checksumUrl": "https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-20260901.0.x86_64.qcow2.SHA256SUM",
        "checksumAlgorithm": "sha256",
    },
    "centos-stream-10-genericcloud-amd64": {
        "filename": "CentOS-Stream-GenericCloud-10-20260901.0.x86_64.qcow2",
        "url": "https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-20260901.0.x86_64.qcow2",
        "checksumUrl": "https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-20260901.0.x86_64.qcow2.SHA256SUM",
        "checksumAlgorithm": "sha256",
    },
}


class ContractError(Exception):
    def __init__(self, code: str, message: str, details: Optional[Mapping[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})


def safe_process_environment(for_builder: bool = False) -> Dict[str, str]:
    environment = dict(os.environ)
    environment["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    for name in (
        "BASH_ENV",
        "BASHOPTS",
        "BASH_COMPAT",
        "BASH_XTRACEFD",
        "SHELLOPTS",
        "ENV",
        "IFS",
        "PS4",
        "PROMPT_COMMAND",
        "CDPATH",
        "GLOBIGNORE",
        "CURL_HOME",
        "SSLKEYLOGFILE",
        "GCONV_PATH",
        "LOCPATH",
        "NLSPATH",
        "PERL5LIB",
        "PERL5OPT",
        "PERL_UNICODE",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONIOENCODING",
        "PYTHONWARNINGS",
        "LANGUAGE",
    ):
        environment.pop(name, None)
    for name in list(environment):
        if name.startswith("BASH_FUNC_") or name.startswith("LD_"):
            environment.pop(name, None)
    if for_builder:
        for name in BUILDER_SETTING_KEYS:
            environment.pop(name, None)
    return environment


def _strict_object(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("CATALOG_DUPLICATE_KEY", "catalog contains a duplicate JSON key", {"key": key})
        result[key] = value
    return result


def _require_keys(value: Any, expected: Iterable[str], context: str) -> MutableMapping[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("CATALOG_SCHEMA_INVALID", f"{context} must be an object")
    expected_set = set(expected)
    actual = set(value)
    if actual != expected_set:
        raise ContractError(
            "CATALOG_SCHEMA_INVALID",
            f"{context} has unexpected or missing fields",
            {"context": context, "missing": sorted(expected_set - actual), "unknown": sorted(actual - expected_set)},
        )
    return value


def _require_string(value: Any, context: str, max_length: int = 500) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length or any(ord(char) < 32 for char in value):
        raise ContractError("CATALOG_SCHEMA_INVALID", f"{context} must be a non-empty safe string")
    return value


def _validate_digest(value: Any, algorithm: str, context: str) -> str:
    expected_length = 64 if algorithm == "sha256" else 128
    if not isinstance(value, str) or len(value) != expected_length or not HEX_RE.fullmatch(value):
        raise ContractError("CATALOG_DIGEST_INVALID", f"{context} must be a lowercase {algorithm} digest")
    return value


def _validate_url_spec(url_key: str, spec: Mapping[str, str]) -> None:
    filename = spec["filename"]
    if Path(filename).name != filename or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", filename):
        raise ContractError("BUILTIN_SOURCE_INVALID", "built-in source filename is unsafe", {"urlKey": url_key})
    for field in ("url", "checksumUrl"):
        parsed = urlsplit(spec[field])
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.hostname not in ALLOWED_SOURCE_HOSTS
            or parsed.username
            or parsed.password
            or parsed.port not in (None, 443)
            or parsed.query
            or parsed.fragment
        ):
            raise ContractError("BUILTIN_SOURCE_INVALID", "built-in source URL is not strict HTTPS", {"urlKey": url_key, "field": field})
    if Path(urlsplit(spec["url"]).path).name != filename:
        raise ContractError("BUILTIN_SOURCE_INVALID", "built-in source URL filename does not match", {"urlKey": url_key})
    if spec["checksumAlgorithm"] not in ("sha256", "sha512"):
        raise ContractError("BUILTIN_SOURCE_INVALID", "built-in checksum algorithm is unsupported", {"urlKey": url_key})


def load_catalog(path: Path = CATALOG_PATH) -> Dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ContractError("CATALOG_UNREADABLE", "bundled template catalog cannot be read", {"path": str(path), "reason": str(error)})
    if len(raw) > 1024 * 1024:
        raise ContractError("CATALOG_TOO_LARGE", "bundled template catalog exceeds 1 MiB")
    try:
        catalog = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except ContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError("CATALOG_JSON_INVALID", "bundled template catalog is not valid UTF-8 JSON", {"reason": str(error)})

    root = _require_keys(
        catalog,
        ("schemaVersion", "catalogId", "catalogRevision", "issuedAt", "websitePath", "items"),
        "catalog",
    )
    if root["schemaVersion"] != CATALOG_SCHEMA:
        raise ContractError("CATALOG_VERSION_UNSUPPORTED", "unsupported catalog schemaVersion")
    if root["catalogId"] != "ppflight-proxmox-templates" or root["websitePath"] != "/vps/proxmox-templates":
        raise ContractError("CATALOG_IDENTITY_INVALID", "catalog identity or website path is not canonical")
    if not isinstance(root["catalogRevision"], str) or not REVISION_RE.fullmatch(root["catalogRevision"]):
        raise ContractError("CATALOG_REVISION_INVALID", "catalogRevision must be YYYY-MM-DD.N")
    if not isinstance(root["issuedAt"], str) or not RFC3339_RE.fullmatch(root["issuedAt"]):
        raise ContractError("CATALOG_ISSUED_AT_INVALID", "issuedAt must be an RFC 3339 timestamp")
    try:
        issued_at = datetime.fromisoformat(root["issuedAt"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError("CATALOG_ISSUED_AT_INVALID", "issuedAt must be an RFC 3339 timestamp", {"reason": str(error)})
    if issued_at.tzinfo is None:
        raise ContractError("CATALOG_ISSUED_AT_INVALID", "issuedAt must include a timezone")
    if not isinstance(root["items"], list) or not root["items"]:
        raise ContractError("CATALOG_SCHEMA_INVALID", "catalog.items must be a non-empty array")

    for url_key, spec in URL_SPECS.items():
        _validate_url_spec(url_key, spec)

    template_refs: set[str] = set()
    selectors: set[str] = set()
    vmids: set[int] = set()
    placeholder_ips: set[str] = set()
    for index, raw_item in enumerate(root["items"]):
        context = f"catalog.items[{index}]"
        item = _require_keys(
            raw_item,
            ("templateRef", "version", "displayName", "aliases", "architecture", "guestType", "source", "target", "minimumBytes", "build"),
            context,
        )
        template_ref = _require_string(item["templateRef"], f"{context}.templateRef", 80)
        if not SAFE_KEY_RE.fullmatch(template_ref) or template_ref in template_refs:
            raise ContractError("CATALOG_TEMPLATE_REF_INVALID", "templateRef must be unique and canonical", {"templateRef": template_ref})
        template_refs.add(template_ref)
        if template_ref in selectors:
            raise ContractError("CATALOG_SELECTOR_DUPLICATE", "templateRef collides with another selector", {"selector": template_ref})
        selectors.add(template_ref)
        version = _require_string(item["version"], f"{context}.version", 40)
        if not VERSION_RE.fullmatch(version):
            raise ContractError("CATALOG_VERSION_INVALID", "template version is not canonical", {"templateRef": template_ref})
        _require_string(item["displayName"], f"{context}.displayName", 80)
        if not isinstance(item["aliases"], list):
            raise ContractError("CATALOG_SCHEMA_INVALID", f"{context}.aliases must be an array")
        for alias in item["aliases"]:
            if not isinstance(alias, str) or not SAFE_KEY_RE.fullmatch(alias) or alias in selectors:
                raise ContractError("CATALOG_SELECTOR_DUPLICATE", "aliases must be safe and globally unique", {"alias": alias})
            selectors.add(alias)
        if item["architecture"] != "amd64" or item["guestType"] != "qemu":
            raise ContractError("CATALOG_GUEST_UNSUPPORTED", "only amd64 qemu templates are supported")

        source = _require_keys(item["source"], ("kind", "urlKey", "sha256", "format", "upstreamChecksum"), f"{context}.source")
        if source["kind"] != "official-cloud-image" or source["format"] != "qcow2":
            raise ContractError("CATALOG_SOURCE_UNSUPPORTED", "source kind or format is unsupported", {"templateRef": template_ref})
        url_key = _require_string(source["urlKey"], f"{context}.source.urlKey", 100)
        if url_key not in URL_SPECS:
            raise ContractError("CATALOG_URL_KEY_UNKNOWN", "catalog refers to an unknown built-in urlKey", {"urlKey": url_key})
        sha256 = _validate_digest(source["sha256"], "sha256", f"{context}.source.sha256")
        upstream = _require_keys(source["upstreamChecksum"], ("algorithm", "value"), f"{context}.source.upstreamChecksum")
        if upstream["algorithm"] != URL_SPECS[url_key]["checksumAlgorithm"]:
            raise ContractError("CATALOG_CHECKSUM_ALGORITHM_MISMATCH", "catalog checksum algorithm does not match urlKey", {"urlKey": url_key})
        upstream_value = _validate_digest(upstream["value"], upstream["algorithm"], f"{context}.source.upstreamChecksum.value")
        if upstream["algorithm"] == "sha256" and upstream_value != sha256:
            raise ContractError("CATALOG_DIGEST_MISMATCH", "source sha256 differs from upstream SHA-256", {"templateRef": template_ref})

        target = _require_keys(item["target"], ("vmid", "osType", "diskBus", "agentEnabled"), f"{context}.target")
        vmid = target["vmid"]
        if isinstance(vmid, bool) or not isinstance(vmid, int) or not 100 <= vmid <= 999999999 or vmid in vmids:
            raise ContractError("CATALOG_VMID_INVALID", "target VMID must be unique and in PVE range", {"vmid": vmid})
        vmids.add(vmid)
        if target["osType"] != "l26" or target["diskBus"] != "scsi0" or target["agentEnabled"] is not True:
            raise ContractError("CATALOG_TARGET_UNSUPPORTED", "target settings are not supported", {"templateRef": template_ref})
        if isinstance(item["minimumBytes"], bool) or not isinstance(item["minimumBytes"], int) or item["minimumBytes"] < 64 * 1024 * 1024:
            raise ContractError("CATALOG_MINIMUM_BYTES_INVALID", "minimumBytes is too small", {"templateRef": template_ref})

        build = _require_keys(item["build"], ("family", "templateName", "placeholderIPv4", "description"), f"{context}.build")
        if build["family"] not in ("debian", "rhel") or build["templateName"] != template_ref:
            raise ContractError("CATALOG_BUILD_INVALID", "build family or templateName is invalid", {"templateRef": template_ref})
        placeholder = _require_string(build["placeholderIPv4"], f"{context}.build.placeholderIPv4", 15)
        try:
            address = ipaddress.ip_address(placeholder)
        except ValueError:
            raise ContractError("CATALOG_PLACEHOLDER_IP_INVALID", "placeholderIPv4 is invalid", {"templateRef": template_ref})
        if address not in TEST_NET or address in (TEST_NET.network_address, TEST_NET.broadcast_address) or placeholder in placeholder_ips:
            raise ContractError("CATALOG_PLACEHOLDER_IP_INVALID", "placeholderIPv4 must be unique RFC 5737 space", {"templateRef": template_ref})
        placeholder_ips.add(placeholder)
        description = _require_string(build["description"], f"{context}.build.description", 240)
        if "|" in description:
            raise ContractError("CATALOG_BUILD_INVALID", "description contains a reserved delimiter", {"templateRef": template_ref})

    selector_vmid_collisions = sorted(selectors & {str(vmid) for vmid in vmids})
    if selector_vmid_collisions:
        raise ContractError(
            "CATALOG_SELECTOR_DUPLICATE",
            "a templateRef or alias collides with a VMID selector",
            {"selectors": selector_vmid_collisions},
        )

    root["_catalogSha256"] = hashlib.sha256(raw).hexdigest()
    return dict(root)


def catalog_without_internal_fields(catalog: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in catalog.items() if not key.startswith("_")}


def select_items(catalog: Mapping[str, Any], selector_text: str) -> List[Mapping[str, Any]]:
    items = list(catalog["items"])
    if selector_text == "all":
        return items
    lookup: Dict[str, Mapping[str, Any]] = {}
    for item in items:
        lookup[item["templateRef"]] = item
        lookup[str(item["target"]["vmid"])] = item
        for alias in item["aliases"]:
            lookup[alias] = item
    selected: List[Mapping[str, Any]] = []
    seen: set[str] = set()
    tokens = selector_text.split(",")
    if not tokens or any(not token for token in tokens):
        raise ContractError("ITEM_SELECTOR_INVALID", "--items must be all or a comma-separated selector list")
    for token in tokens:
        item = lookup.get(token)
        if item is None:
            raise ContractError("ITEM_NOT_IN_CATALOG", "requested item is not in the bundled catalog", {"selector": token})
        if item["templateRef"] in seen:
            raise ContractError("ITEM_SELECTOR_DUPLICATE", "requested item appears more than once", {"templateRef": item["templateRef"]})
        seen.add(item["templateRef"])
        selected.append(item)
    return selected


def catalog_rows(catalog: Mapping[str, Any]) -> List[str]:
    rows: List[str] = []
    for item in catalog["items"]:
        source = item["source"]
        spec = URL_SPECS[source["urlKey"]]
        upstream = source["upstreamChecksum"]
        fields = (
            str(item["target"]["vmid"]),
            item["build"]["templateName"],
            spec["filename"],
            spec["url"],
            spec["checksumUrl"],
            upstream["algorithm"],
            upstream["value"],
            source["sha256"],
            str(item["minimumBytes"]),
            item["build"]["family"],
            item["build"]["placeholderIPv4"],
            item["build"]["description"],
            item["version"],
            ",".join(item["aliases"]),
        )
        if any("|" in field or "\n" in field or "\r" in field for field in fields):
            raise ContractError("CATALOG_ROW_UNSAFE", "catalog contains a reserved row character", {"templateRef": item["templateRef"]})
        rows.append("|".join(fields))
    return rows


class CommandRunner:
    def run(self, argv: Sequence[str], check: bool = True, timeout: Optional[int] = 120) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                list(argv),
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                env=safe_process_environment(),
                timeout=timeout,
            )
        except FileNotFoundError:
            raise ContractError("PVE_COMMAND_NOT_FOUND", "required local PVE command was not found", {"program": argv[0]})
        except subprocess.TimeoutExpired:
            raise ContractError("PVE_COMMAND_TIMEOUT", "local PVE command timed out", {"program": argv[0]})
        if check and result.returncode != 0:
            raise ContractError(
                "PVE_COMMAND_FAILED",
                "local PVE command failed",
                {"program": argv[0], "returnCode": result.returncode, "stderr": result.stderr[-2000:]},
            )
        return result

    def json(self, argv: Sequence[str], timeout: Optional[int] = 120) -> Any:
        result = self.run(argv, timeout=timeout)
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ContractError("PVE_JSON_INVALID", "local PVE command returned invalid JSON", {"program": argv[0], "reason": str(error)})
        if isinstance(value, dict) and set(value) == {"data"}:
            return value["data"]
        return value


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).lower() in ("1", "true", "yes", "on", "active", "enabled")


def _content_types(value: Any) -> List[str]:
    if isinstance(value, list):
        entries = value
    elif isinstance(value, str):
        entries = value.split(",")
    else:
        entries = []
    return sorted({str(entry).strip() for entry in entries if str(entry).strip()})


def _int_or_none(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _storage_content_path(
    runner: CommandRunner,
    storage_id: str,
    content_type: str,
    probe_name: str,
) -> Optional[str]:
    result = runner.run(("pvesm", "path", f"{storage_id}:{content_type}/{probe_name}"), check=False)
    if result.returncode != 0:
        return None
    resolved = result.stdout.strip()
    path = Path(resolved)
    if (
        not resolved.startswith("/")
        or "\n" in resolved
        or "\r" in resolved
        or "\x00" in resolved
        or ".." in path.parts
        or path.name != probe_name
    ):
        return None
    return resolved


def _image_storage_path_reasons(runner: CommandRunner, storage_id: str) -> List[str]:
    reasons: List[str] = []
    for content_type, probe_name in (
        ("iso", "ppflight-cloudinit-probe.iso"),
        ("snippets", "ppflight-cloudinit-probe.yaml"),
    ):
        if _storage_content_path(runner, storage_id, content_type, probe_name) is None:
            reasons.append(f"IMAGE_STORAGE_{content_type.upper()}_PATH_UNSUPPORTED")
    return reasons


def _storage_content_remediations(
    storage_id: str,
    storage_type: str,
    content: Sequence[str],
    enabled: bool,
    active: bool,
) -> List[Dict[str, Any]]:
    required = sorted({"iso", "snippets"} - set(content))
    if (
        not required
        or not enabled
        or not active
        or storage_type.lower() not in FILE_CONTENT_STORAGE_TYPES
        or not STORAGE_ID_RE.fullmatch(storage_id)
        or any(not CONTENT_TYPE_RE.fullmatch(entry) for entry in content)
    ):
        return []
    current_content = ",".join(content)
    required_content = ",".join(required)
    proposed_content = ",".join(sorted(set(content) | set(required)))
    return [
        {
            "code": "ENABLE_STORAGE_CONTENT",
            "storageId": storage_id,
            "currentContent": current_content,
            "requiredContent": required_content,
            "proposedContent": proposed_content,
            "command": {
                "program": "pvesm",
                "argv": ["pvesm", "set", storage_id, "--content", proposed_content],
            },
            "automatic": False,
        }
    ]


def _local_pve_node(runner: CommandRunner) -> str:
    cluster_status = runner.json(("pvesh", "get", "/cluster/status", "--output-format", "json"))
    if not isinstance(cluster_status, list):
        raise ContractError("PVE_NODE_RESPONSE_INVALID", "PVE cluster status did not return an array")
    local_nodes = [
        row
        for row in cluster_status
        if isinstance(row, dict)
        and str(row.get("type", "")).lower() == "node"
        and _as_bool(row.get("local"), False)
    ]
    if len(local_nodes) != 1:
        raise ContractError(
            "PVE_LOCAL_NODE_INVALID",
            "PVE cluster status did not identify exactly one local node",
            {"localNodeCount": len(local_nodes)},
        )
    node_name = str(local_nodes[0].get("name", local_nodes[0].get("node", "")))
    if not PVE_NODE_RE.fullmatch(node_name):
        raise ContractError("PVE_LOCAL_NODE_INVALID", "PVE returned an invalid local node name")
    return node_name


def discover_storages(runner: CommandRunner) -> List[Dict[str, Any]]:
    configs = runner.json(("pvesh", "get", "/storage", "--output-format", "json"))
    local_node = _local_pve_node(runner)
    statuses = runner.json(("pvesh", "get", f"/nodes/{local_node}/storage", "--output-format", "json"))
    if not isinstance(configs, list) or not isinstance(statuses, list):
        raise ContractError("PVE_STORAGE_RESPONSE_INVALID", "PVE storage discovery did not return arrays")
    status_by_id = {str(row.get("storage")): row for row in statuses if isinstance(row, dict) and row.get("storage")}
    discovered: List[Dict[str, Any]] = []
    for config in configs:
        if not isinstance(config, dict) or not config.get("storage"):
            raise ContractError("PVE_STORAGE_RESPONSE_INVALID", "PVE returned a storage without an ID")
        storage_id = str(config["storage"])
        if not STORAGE_ID_RE.fullmatch(storage_id):
            raise ContractError(
                "PVE_STORAGE_RESPONSE_INVALID",
                "PVE returned an invalid storage ID",
                {"storageId": storage_id},
            )
        status = status_by_id.get(storage_id, {})
        storage_type = str(config.get("type", status.get("type", "unknown")))
        content = _content_types(config.get("content"))
        enabled = not _as_bool(config.get("disable"), False)
        active = str(status.get("status", "")).lower() == "active" or _as_bool(status.get("active"), False)
        available_value = _int_or_none(status.get("avail", status.get("available")))
        role_content = {"image": {"iso", "snippets"}, "template": {"images"}, "backup": {"backup"}}
        roles: Dict[str, Dict[str, Any]] = {}
        for role, required_content in role_content.items():
            reasons: List[str] = []
            if not enabled:
                reasons.append("STORAGE_DISABLED")
            if not active:
                reasons.append("STORAGE_INACTIVE")
            reasons.extend(f"MISSING_CONTENT_{entry.upper()}" for entry in sorted(required_content - set(content)))
            if role == "image" and not reasons:
                reasons.extend(_image_storage_path_reasons(runner, storage_id))
            roles[role] = {"allowed": not reasons, "reasons": reasons}
        discovered.append(
            {
                "storageId": storage_id,
                "type": storage_type,
                "contentTypes": content,
                "enabled": enabled,
                "active": active,
                "shared": _as_bool(config.get("shared", status.get("shared")), False),
                "availableBytes": str(available_value if available_value is not None else 0),
                "availableBytesKnown": available_value is not None,
                "roleEligibility": roles,
                "remediations": _storage_content_remediations(
                    storage_id,
                    storage_type,
                    content,
                    enabled,
                    active,
                ),
            }
        )
    return sorted(discovered, key=lambda row: row["storageId"])


def validate_storage_id(value: str, argument: str) -> str:
    if not STORAGE_ID_RE.fullmatch(value):
        raise ContractError("STORAGE_ID_INVALID", f"{argument} is not a valid PVE storage ID", {"storageId": value})
    return value


def validate_bridge(value: str) -> str:
    if not BRIDGE_RE.fullmatch(value):
        raise ContractError("BRIDGE_INVALID", "bridge name contains unsupported characters", {"bridge": value})
    return value


def validate_uuid(value: Optional[str], field: str) -> str:
    if value is None:
        return str(uuid.uuid4())
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise ContractError("UUID_INVALID", f"{field} must be a UUID", {"field": field})
    canonical = str(parsed)
    if canonical != value.lower():
        raise ContractError("UUID_INVALID", f"{field} must use canonical UUID form", {"field": field})
    return canonical


def build_request(args: argparse.Namespace, catalog: Mapping[str, Any], items: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    image_storage = validate_storage_id(args.image_storage, "imageStorage")
    template_storage = validate_storage_id(args.template_storage, "templateStorage")
    external_bridge = validate_bridge(args.bridge)
    internal_bridge = validate_bridge(args.internal_bridge) if args.internal_bridge else None
    if internal_bridge == external_bridge:
        raise ContractError(
            "BRIDGE_ROLE_CONFLICT",
            "external and internal template bridges must be different",
            {"externalBridge": external_bridge, "internalBridge": internal_bridge},
        )
    if args.backup_policy == "required":
        if not args.backup_storage:
            raise ContractError("BACKUP_STORAGE_REQUIRED", "backupPolicy=required requires --backup-storage")
        backup_storage = validate_storage_id(args.backup_storage, "backupStorage")
    elif args.backup_policy == "disabled":
        if args.backup_storage is not None:
            raise ContractError("BACKUP_STORAGE_FORBIDDEN", "backupPolicy=disabled must not include --backup-storage")
        backup_storage = None
    else:
        raise ContractError("BACKUP_POLICY_INVALID", "backupPolicy must be required or disabled")
    if args.execute:
        if not args.request_id or not args.operation_id:
            raise ContractError(
                "OPERATION_CONFIRMATION_REQUIRED",
                "--execute requires the requestId and operationId from the confirmed plan",
            )
        if not args.expected_catalog_revision or not args.expected_catalog_sha256:
            raise ContractError(
                "CATALOG_CONFIRMATION_REQUIRED",
                "--execute requires --expected-catalog-revision and --expected-catalog-sha256 from the confirmed plan",
            )
        if args.expected_catalog_revision != catalog["catalogRevision"] or args.expected_catalog_sha256 != catalog["_catalogSha256"]:
            raise ContractError(
                "CATALOG_DRIFT",
                "bundled catalog changed after the plan was confirmed",
                {
                    "expectedCatalogRevision": args.expected_catalog_revision,
                    "actualCatalogRevision": catalog["catalogRevision"],
                    "expectedCatalogSha256": args.expected_catalog_sha256,
                    "actualCatalogSha256": catalog["_catalogSha256"],
                },
            )
    request: Dict[str, Any] = {
        "schemaVersion": REQUEST_SCHEMA,
        "requestId": validate_uuid(args.request_id, "requestId"),
        "operationId": validate_uuid(args.operation_id, "operationId"),
        "catalogRevision": catalog["catalogRevision"],
        "imageStorage": image_storage,
        "templateStorage": template_storage,
        "backupPolicy": args.backup_policy,
        "externalBridge": external_bridge,
        "items": [
            {
                "templateRef": item["templateRef"],
                "version": item["version"],
                "sha256": item["source"]["sha256"],
                "targetVmid": item["target"]["vmid"],
            }
            for item in items
        ],
    }
    if backup_storage is not None:
        request["backupStorage"] = backup_storage
    if internal_bridge is not None:
        request["internalBridge"] = internal_bridge
    return request


def _storage_or_error(storages: Sequence[Mapping[str, Any]], storage_id: str, role: str) -> Mapping[str, Any]:
    storage = next((row for row in storages if row["storageId"] == storage_id), None)
    if storage is None:
        raise ContractError("STORAGE_NOT_FOUND", "selected PVE storage does not exist", {"storageId": storage_id, "role": role})
    if not storage["enabled"]:
        raise ContractError("STORAGE_DISABLED", "selected PVE storage is disabled", {"storageId": storage_id, "role": role})
    if not storage["active"]:
        raise ContractError("STORAGE_INACTIVE", "selected PVE storage is not active", {"storageId": storage_id, "role": role})
    required = {"image": {"iso", "snippets"}, "template": {"images"}, "backup": {"backup"}}[role]
    missing = sorted(required - set(storage["contentTypes"]))
    if missing:
        raise ContractError(
            f"{role.upper()}_STORAGE_CONTENT_UNSUPPORTED",
            "selected PVE storage lacks required content types",
            {"storageId": storage_id, "role": role, "missingContentTypes": missing},
        )
    eligibility = storage["roleEligibility"][role]
    if not eligibility["allowed"]:
        reasons = list(eligibility["reasons"])
        raise ContractError(
            reasons[0] if reasons else "STORAGE_ROLE_UNSUPPORTED",
            "selected PVE storage cannot be used for this role",
            {"storageId": storage_id, "role": role, "reasons": reasons},
        )
    return storage


def _resolve_image_cache(runner: CommandRunner, storage_id: str) -> str:
    iso_probe = _storage_content_path(runner, storage_id, "iso", "ppflight-cloudinit-probe.iso")
    if iso_probe is None:
        raise ContractError(
            "IMAGE_STORAGE_ISO_PATH_UNSUPPORTED",
            "imageStorage ISO content does not resolve to a safe local filesystem path",
            {"storageId": storage_id},
        )
    if _storage_content_path(runner, storage_id, "snippets", "ppflight-cloudinit-probe.yaml") is None:
        raise ContractError(
            "IMAGE_STORAGE_SNIPPETS_PATH_UNSUPPORTED",
            "imageStorage snippets content does not resolve to a safe local filesystem path",
            {"storageId": storage_id},
        )
    return str(Path(iso_probe).parent / "ppflight-cloudinit-cache")


def _existing_vmids(runner: CommandRunner) -> Dict[int, Mapping[str, Any]]:
    resources = runner.json(("pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"))
    if not isinstance(resources, list):
        raise ContractError("PVE_RESOURCE_RESPONSE_INVALID", "PVE VM discovery did not return an array")
    existing: Dict[int, Mapping[str, Any]] = {}
    for resource in resources:
        if not isinstance(resource, dict) or "vmid" not in resource:
            continue
        try:
            existing[int(resource["vmid"])] = resource
        except (TypeError, ValueError):
            raise ContractError("PVE_RESOURCE_RESPONSE_INVALID", "PVE returned a non-numeric VMID")
    return existing


def _error_dict(error: ContractError) -> Dict[str, Any]:
    return {"errorCode": error.code, "message": error.message, "details": error.details}


def prepare_plan(args: argparse.Namespace, catalog: Mapping[str, Any], runner: CommandRunner) -> Dict[str, Any]:
    items = select_items(catalog, args.items)
    request = build_request(args, catalog, items)
    bridge = request["externalBridge"]
    internal_bridge = request.get("internalBridge")
    storages = discover_storages(runner)
    errors: List[Dict[str, Any]] = []
    selected_storages: Dict[str, Mapping[str, Any]] = {}
    for role, field in (("image", "imageStorage"), ("template", "templateStorage")):
        try:
            selected_storages[role] = _storage_or_error(storages, request[field], role)
        except ContractError as error:
            errors.append(_error_dict(error))
    if request["backupPolicy"] == "required":
        try:
            selected_storages["backup"] = _storage_or_error(storages, request["backupStorage"], "backup")
        except ContractError as error:
            errors.append(_error_dict(error))

    required_bytes = sum(int(item["minimumBytes"]) for item in items)
    for role in ("image", "template", "backup"):
        storage = selected_storages.get(role)
        if storage is None:
            continue
        available = int(storage["availableBytes"])
        if storage["availableBytesKnown"] and available < required_bytes:
            error = ContractError(
                f"{role.upper()}_STORAGE_INSUFFICIENT_SPACE",
                "selected storage reports less available space than the catalog minimum",
                {"storageId": storage["storageId"], "availableBytes": str(available), "minimumBytes": str(required_bytes)},
            )
            errors.append(_error_dict(error))

    cache_dir: Optional[str] = None
    if "image" in selected_storages:
        try:
            cache_dir = _resolve_image_cache(runner, request["imageStorage"])
        except ContractError as error:
            errors.append(_error_dict(error))

    for role, selected_bridge in (("external", bridge), ("internal", internal_bridge)):
        if selected_bridge is None:
            continue
        bridge_result = runner.run(("ip", "link", "show", "dev", selected_bridge), check=False)
        if bridge_result.returncode != 0:
            errors.append(
                _error_dict(
                    ContractError(
                        f"{role.upper()}_BRIDGE_NOT_FOUND",
                        f"selected PVE {role} bridge does not exist",
                        {"role": role, "bridge": selected_bridge},
                    )
                )
            )

    existing = _existing_vmids(runner)
    item_results: List[Dict[str, Any]] = []
    conflict_codes: Dict[int, str] = {}
    for item in items:
        vmid = item["target"]["vmid"]
        if vmid in existing:
            conflict_codes[vmid] = "VMID_CONFLICT"
            errors.append(
                _error_dict(
                    ContractError(
                        "VMID_CONFLICT",
                        "catalog target VMID already exists; bootstrap never replaces an existing VM or template",
                        {"targetVmid": vmid, "existingName": existing[vmid].get("name"), "existingType": existing[vmid].get("type")},
                    )
                )
            )
        spec = URL_SPECS[item["source"]["urlKey"]]
        source_volume = str(Path(cache_dir) / spec["filename"]) if cache_dir else None
        item_results.append(
            {
                "templateRef": item["templateRef"],
                "version": item["version"],
                "sha256": item["source"]["sha256"],
                "targetVmid": vmid,
                "phase": "plan",
                "state": "blocked" if vmid in conflict_codes else "planned",
                "errorCode": conflict_codes.get(vmid),
                "sourceVolume": source_volume,
                "templateVolume": None,
                "backupVolume": None,
                "upid": None,
            }
        )

    if errors:
        for item_result in item_results:
            if item_result["state"] != "blocked":
                item_result["state"] = "blocked"
                item_result["errorCode"] = errors[0]["errorCode"]
    builder_argv = [
        "/usr/bin/bash",
        str(BUILDER_PATH),
        "--image-storage",
        request["templateStorage"],
        "--file-storage",
        request["imageStorage"],
        "--bridge",
        bridge,
        "--only",
        ",".join(item["templateRef"] for item in items),
        "--expected-catalog-revision",
        catalog["catalogRevision"],
        "--expected-catalog-sha256",
        catalog["_catalogSha256"],
        "--no-backup",
    ]
    if internal_bridge is not None:
        builder_argv.extend(("--internal-bridge", internal_bridge))
    return {
        "schemaVersion": RESULT_SCHEMA,
        "mode": "execute" if args.execute else "plan",
        "state": "blocked" if errors else "ready",
        "executable": not errors,
        "catalog": {
            "catalogId": catalog["catalogId"],
            "catalogRevision": catalog["catalogRevision"],
            "catalogSha256": catalog["_catalogSha256"],
            "websitePath": catalog["websitePath"],
            "matchFields": ["templateRef", "version", "sha256", "architecture", "guestType"],
        },
        "request": request,
        "bridge": bridge,
        "internalBridge": internal_bridge,
        "requiredBytes": str(required_bytes),
        "selectedStorages": selected_storages,
        "items": item_results,
        "errors": errors,
        "command": {"program": builder_argv[0], "argv": builder_argv},
    }


def _stream_process(argv: Sequence[str]) -> int:
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            env=safe_process_environment(for_builder=True),
            bufsize=1,
        )
    except FileNotFoundError:
        raise ContractError("BUILDER_COMMAND_NOT_FOUND", "template builder command was not found", {"program": argv[0]})
    assert process.stdout is not None
    for line in process.stdout:
        sys.stderr.write(line)
        sys.stderr.flush()
    return process.wait()


def _template_volume(runner: CommandRunner, vmid: int) -> Optional[str]:
    result = runner.run(("qm", "config", str(vmid)), check=False)
    if result.returncode != 0:
        return None
    lines = result.stdout.splitlines()
    if "template: 1" not in lines:
        return None
    tag_line = next((line for line in lines if line.startswith("tags: ")), "")
    tags = re.split(r"[;,]", tag_line[len("tags: ") :]) if tag_line else []
    if "ppflight-cloudinit" not in tags:
        return None
    # The builder writes this tag only after virt-customize has installed the
    # package and an offline guest filesystem check has verified its package
    # database, daemon binary and enabled systemd unit.  PVE's agent device
    # flag alone is deliberately insufficient for template eligibility.
    if "ppflight-qga-preinstalled" not in tags:
        return None
    if not any(line.startswith("agent: enabled=1") for line in lines):
        return None
    for line in lines:
        if line.startswith("scsi0: "):
            return line[len("scsi0: ") :].split(",", 1)[0]
    return None


def _backup_volumes(runner: CommandRunner, storage_id: str, vmid: int) -> List[str]:
    values = runner.json(("pvesm", "list", storage_id, "--content", "backup", "--vmid", str(vmid), "--output-format", "json"))
    if not isinstance(values, list):
        raise ContractError("PVE_BACKUP_RESPONSE_INVALID", "PVE backup listing did not return an array", {"targetVmid": vmid})
    return sorted(str(value["volid"]) for value in values if isinstance(value, dict) and value.get("volid"))


def _extract_upid(value: Any) -> str:
    if isinstance(value, str):
        upid = value
    elif isinstance(value, dict) and isinstance(value.get("upid"), str):
        upid = value["upid"]
    else:
        raise ContractError("PVE_BACKUP_UPID_INVALID", "PVE did not return a backup UPID")
    if not UPID_RE.fullmatch(upid):
        raise ContractError("PVE_BACKUP_UPID_INVALID", "PVE returned an unsafe backup UPID")
    return upid


def _wait_for_backup(runner: CommandRunner, node: str, upid: str, timeout_seconds: int = 21600) -> None:
    deadline = time.monotonic() + timeout_seconds
    next_progress = time.monotonic()
    while True:
        status = runner.json(("pvesh", "get", f"/nodes/{node}/tasks/{upid}/status", "--output-format", "json"))
        if not isinstance(status, dict):
            raise ContractError("PVE_BACKUP_STATUS_INVALID", "PVE backup task status was not an object", {"upid": upid})
        if status.get("status") == "stopped":
            if status.get("exitstatus") != "OK":
                raise ContractError("BACKUP_TASK_FAILED", "PVE backup task did not finish successfully", {"upid": upid, "exitStatus": status.get("exitstatus")})
            return
        now = time.monotonic()
        if now >= deadline:
            raise ContractError("BACKUP_TASK_TIMEOUT", "PVE backup task exceeded six hours", {"upid": upid})
        if now >= next_progress:
            sys.stderr.write(f"Waiting for backup task {upid}\n")
            sys.stderr.flush()
            next_progress = now + 30
        time.sleep(2)


def _run_backup(runner: CommandRunner, storage_id: str, vmid: int) -> Tuple[str, Optional[str]]:
    node_result = runner.run(("pvecm", "nodename"))
    node = node_result.stdout.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", node):
        raise ContractError("PVE_NODE_INVALID", "local PVE node name is invalid")
    before = set(_backup_volumes(runner, storage_id, vmid))
    response = runner.json(
        (
            "pvesh",
            "create",
            f"/nodes/{node}/vzdump",
            "--vmid",
            str(vmid),
            "--storage",
            storage_id,
            "--mode",
            "snapshot",
            "--compress",
            "zstd",
            "--output-format",
            "json",
        ),
        timeout=120,
    )
    upid = _extract_upid(response)
    try:
        _wait_for_backup(runner, node, upid)
        after = set(_backup_volumes(runner, storage_id, vmid))
    except ContractError as error:
        error.details.setdefault("upid", upid)
        raise
    created = sorted(after - before)
    return upid, created[-1] if created else None


def execute_plan(plan: Dict[str, Any], runner: CommandRunner) -> Tuple[Dict[str, Any], int]:
    if not plan["executable"]:
        return plan, 2
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        error = ContractError("ROOT_REQUIRED", "--execute must run as root on the PVE node")
        plan["state"] = "failed"
        plan["executable"] = False
        plan["errors"].append(_error_dict(error))
        for item in plan["items"]:
            item["state"] = "failed"
            item["errorCode"] = error.code
        return plan, 2

    # prepare_plan already checks cluster-wide VMIDs.  The builder repeats the
    # check immediately before each qm create and is never passed --replace.
    return_code = _stream_process(plan["command"]["argv"])
    if return_code != 0:
        error = ContractError("BUILDER_FAILED", "template builder exited unsuccessfully", {"returnCode": return_code})
        plan["state"] = "failed"
        plan["errors"].append(_error_dict(error))
        for item in plan["items"]:
            item["phase"] = "template"
            item["templateVolume"] = _template_volume(runner, item["targetVmid"])
            if item["templateVolume"]:
                item["state"] = "template-ready"
                item["errorCode"] = None
            else:
                item["state"] = "failed"
                item["errorCode"] = error.code
        return plan, 1

    missing_template_volume = False
    for item in plan["items"]:
        item["phase"] = "template"
        item["state"] = "template-ready"
        item["templateVolume"] = _template_volume(runner, item["targetVmid"])
        if not item["templateVolume"]:
            item["state"] = "failed"
            item["errorCode"] = "TEMPLATE_VOLUME_NOT_FOUND"
            plan["state"] = "failed"
            plan["errors"].append(
                _error_dict(ContractError("TEMPLATE_VOLUME_NOT_FOUND", "created template has no scsi0 volume", {"targetVmid": item["targetVmid"]}))
            )
            missing_template_volume = True
    if missing_template_volume:
        return plan, 1

    if plan["request"]["backupPolicy"] == "required":
        backup_storage = plan["request"]["backupStorage"]
        for item in plan["items"]:
            item["phase"] = "backup"
            item["state"] = "running"
            try:
                upid, volume = _run_backup(runner, backup_storage, item["targetVmid"])
            except ContractError as error:
                item["upid"] = error.details.get("upid")
                item["state"] = "failed"
                item["errorCode"] = error.code
                plan["state"] = "failed"
                plan["errors"].append(_error_dict(error))
                return plan, 1
            item["upid"] = upid
            item["backupVolume"] = volume
            item["phase"] = "complete"
            item["state"] = "succeeded"
    else:
        for item in plan["items"]:
            item["phase"] = "complete"
            item["state"] = "succeeded"

    plan["state"] = "succeeded"
    plan["executable"] = False
    return plan, 0


class JSONArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ContractError("INVALID_ARGUMENT", message)


def make_parser() -> argparse.ArgumentParser:
    parser = JSONArgumentParser(description="Plan or execute PPFlight PVE template bootstrap")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("catalog", help="validate and print the bundled public catalog")
    commands.add_parser("discover", help="discover local PVE storage capabilities")
    bootstrap = commands.add_parser("bootstrap", help="plan by default; add --execute only after confirmation")
    bootstrap.add_argument("--image-storage", required=True, help="active PVE storage supporting iso and snippets")
    bootstrap.add_argument("--template-storage", required=True, help="active PVE storage supporting images")
    bootstrap.add_argument("--backup-policy", required=True, choices=("required", "disabled"))
    bootstrap.add_argument("--backup-storage", help="active PVE storage supporting backup; required by backupPolicy=required")
    bootstrap.add_argument("--items", default="all", help="all or comma-separated catalog refs/aliases/VMIDs")
    bootstrap.add_argument("--bridge", default="vmbr0")
    bootstrap.add_argument("--internal-bridge", help="optional PVE bridge used by template net1")
    bootstrap.add_argument("--request-id")
    bootstrap.add_argument("--operation-id")
    bootstrap.add_argument("--expected-catalog-revision", help="catalogRevision copied from the confirmed plan")
    bootstrap.add_argument("--expected-catalog-sha256", help="catalogSha256 copied from the confirmed plan")
    bootstrap.add_argument("--execute", action="store_true", help="perform the already-confirmed local operation")
    hidden = commands.add_parser("catalog-rows", help=argparse.SUPPRESS)
    hidden.set_defaults(hidden=True)
    metadata = commands.add_parser("catalog-metadata", help=argparse.SUPPRESS)
    metadata.set_defaults(hidden=True)
    return parser


def emit(value: Mapping[str, Any]) -> None:
    json.dump(value, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
    sys.stdout.write("\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = make_parser().parse_args(argv)
        catalog = load_catalog()
        if args.command == "catalog-rows":
            for row in catalog_rows(catalog):
                print(row)
            return 0
        if args.command == "catalog-metadata":
            print(f"{catalog['catalogRevision']}|{catalog['_catalogSha256']}")
            return 0
        if args.command == "catalog":
            emit(
                {
                    "schemaVersion": RESULT_SCHEMA,
                    "mode": "catalog",
                    "state": "succeeded",
                    "catalogSha256": catalog["_catalogSha256"],
                    "catalog": catalog_without_internal_fields(catalog),
                }
            )
            return 0
        runner = CommandRunner()
        if args.command == "discover":
            emit({"schemaVersion": RESULT_SCHEMA, "mode": "discover", "state": "succeeded", "storages": discover_storages(runner)})
            return 0
        plan = prepare_plan(args, catalog, runner)
        if not args.execute:
            emit(plan)
            return 0 if plan["executable"] else 2
        result, return_code = execute_plan(plan, runner)
        emit(result)
        return return_code
    except ContractError as error:
        emit({"schemaVersion": RESULT_SCHEMA, "mode": "error", "state": "failed", "error": _error_dict(error)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

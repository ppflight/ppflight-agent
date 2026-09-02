from __future__ import annotations

import importlib.util
import subprocess
import types
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "bundles"
    / "ppflight-cloudinit"
    / "tools"
    / "ppflight-template-bootstrap.py"
)
SPEC = importlib.util.spec_from_file_location("ppflight_template_bootstrap", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load template bootstrap module")
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


class FakeRunner:
    def __init__(self, cluster_status=None, available_bytes=9876543210, missing_links=None):
        self.calls = []
        self.available_bytes = available_bytes
        self.missing_links = set(missing_links or [])
        self.cluster_status = cluster_status or [
            {"type": "cluster", "name": "lab"},
            {"type": "node", "name": "pve-a", "local": 1},
        ]

    def json(self, argv, timeout=120):
        del timeout
        call = tuple(argv)
        self.calls.append(call)
        if call == ("pvesh", "get", "/storage", "--output-format", "json"):
            return [
                {
                    "storage": "local",
                    "type": "dir",
                    "content": "iso,snippets,images,backup",
                }
            ]
        if call == ("pvesh", "get", "/cluster/status", "--output-format", "json"):
            return self.cluster_status
        if call == ("pvesh", "get", "/nodes/pve-a/storage", "--output-format", "json"):
            return [
                {
                    "storage": "local",
                    "type": "dir",
                    "active": 1,
                    "avail": self.available_bytes,
                    "shared": 0,
                }
            ]
        if call == ("pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"):
            return []
        raise AssertionError(f"unexpected JSON command: {call!r}")

    def run(self, argv, check=True, timeout=120):
        del check, timeout
        call = tuple(argv)
        self.calls.append(call)
        if call[:2] == ("pvesm", "path"):
            probe_name = call[2].split("/", 1)[1]
            return subprocess.CompletedProcess(call, 0, f"/var/lib/vz/{probe_name}\n", "")
        if call[:5] in (
            ("ip", "link", "show", "dev", "vmbr0"),
            ("ip", "link", "show", "dev", "vmbr1"),
        ):
            if call[4] in self.missing_links:
                return subprocess.CompletedProcess(call, 1, "", "not found")
            return subprocess.CompletedProcess(call, 0, "", "")
        raise AssertionError(f"unexpected command: {call!r}")


class StorageDiscoveryTest(unittest.TestCase):
    def test_uses_local_node_storage_json_without_pvesm_status(self):
        runner = FakeRunner()

        storages = BOOTSTRAP.discover_storages(runner)

        self.assertEqual(len(storages), 1)
        self.assertEqual(storages[0]["storageId"], "local")
        self.assertTrue(storages[0]["active"])
        self.assertEqual(storages[0]["availableBytes"], "9876543210")
        self.assertTrue(storages[0]["roleEligibility"]["image"]["allowed"])
        self.assertIn(
            ("pvesh", "get", "/nodes/pve-a/storage", "--output-format", "json"),
            runner.calls,
        )
        self.assertNotIn(
            ("pvesm", "status", "--output-format", "json"),
            runner.calls,
        )

    def test_rejects_missing_local_node(self):
        runner = FakeRunner(cluster_status=[{"type": "cluster", "name": "lab"}])

        with self.assertRaises(BOOTSTRAP.ContractError) as raised:
            BOOTSTRAP.discover_storages(runner)

        self.assertEqual(raised.exception.code, "PVE_LOCAL_NODE_INVALID")

    def test_rejects_ambiguous_local_nodes(self):
        runner = FakeRunner(
            cluster_status=[
                {"type": "node", "name": "pve-a", "local": 1},
                {"type": "node", "name": "pve-b", "local": "1"},
            ]
        )

        with self.assertRaises(BOOTSTRAP.ContractError) as raised:
            BOOTSTRAP.discover_storages(runner)

        self.assertEqual(raised.exception.code, "PVE_LOCAL_NODE_INVALID")


class DualBridgeRequestTest(unittest.TestCase):
    def _arguments(self, **overrides):
        values = {
            "image_storage": "local",
            "template_storage": "local",
            "backup_policy": "disabled",
            "backup_storage": None,
            "bridge": "vmbr0",
            "internal_bridge": "vmbr1",
            "execute": False,
            "request_id": "11111111-1111-4111-8111-111111111111",
            "operation_id": "22222222-2222-4222-8222-222222222222",
            "expected_catalog_revision": None,
            "expected_catalog_sha256": None,
            "items": "ubuntu-24.04",
        }
        values.update(overrides)
        return types.SimpleNamespace(**values)

    def test_request_freezes_external_and_internal_bridge_roles(self):
        catalog = {"catalogRevision": "2026-08-30.1", "_catalogSha256": "a" * 64}
        items = [
            {
                "templateRef": "ubuntu-24.04",
                "version": "24.04",
                "source": {"sha256": "b" * 64},
                "target": {"vmid": 9001},
            }
        ]

        request = BOOTSTRAP.build_request(self._arguments(), catalog, items)

        self.assertEqual(request["externalBridge"], "vmbr0")
        self.assertEqual(request["internalBridge"], "vmbr1")

    def test_request_rejects_same_bridge_for_both_roles(self):
        catalog = {"catalogRevision": "2026-08-30.1", "_catalogSha256": "a" * 64}
        items = [
            {
                "templateRef": "ubuntu-24.04",
                "version": "24.04",
                "source": {"sha256": "b" * 64},
                "target": {"vmid": 9001},
            }
        ]

        with self.assertRaises(BOOTSTRAP.ContractError) as raised:
            BOOTSTRAP.build_request(self._arguments(internal_bridge="vmbr0"), catalog, items)

        self.assertEqual(raised.exception.code, "BRIDGE_ROLE_CONFLICT")

    def test_plan_passes_optional_internal_bridge_to_builder(self):
        plan = BOOTSTRAP.prepare_plan(
            self._arguments(),
            BOOTSTRAP.load_catalog(),
            FakeRunner(available_bytes=100_000_000_000),
        )

        self.assertTrue(plan["executable"])
        self.assertEqual(plan["bridge"], "vmbr0")
        self.assertEqual(plan["internalBridge"], "vmbr1")
        self.assertIn("--internal-bridge", plan["command"]["argv"])
        self.assertEqual(plan["command"]["argv"][-2:], ["--internal-bridge", "vmbr1"])

    def test_plan_keeps_single_nic_compatibility(self):
        plan = BOOTSTRAP.prepare_plan(
            self._arguments(internal_bridge=None),
            BOOTSTRAP.load_catalog(),
            FakeRunner(available_bytes=100_000_000_000),
        )

        self.assertTrue(plan["executable"])
        self.assertIsNone(plan["internalBridge"])
        self.assertNotIn("--internal-bridge", plan["command"]["argv"])

    def test_direct_plan_keeps_missing_internal_bridge_fail_closed(self):
        runner = FakeRunner(
            available_bytes=100_000_000_000,
            missing_links={"vmbr1"},
        )

        plan = BOOTSTRAP.prepare_plan(
            self._arguments(),
            BOOTSTRAP.load_catalog(),
            runner,
        )

        self.assertFalse(plan["executable"])
        self.assertEqual(plan["state"], "blocked")
        self.assertEqual(plan["errors"][0]["errorCode"], "INTERNAL_BRIDGE_NOT_FOUND")
        self.assertTrue(
            all(item["state"] == "blocked" for item in plan["items"])
        )
        self.assertNotIn(
            "/usr/bin/bash",
            [call[0] for call in runner.calls],
        )


if __name__ == "__main__":
    unittest.main()

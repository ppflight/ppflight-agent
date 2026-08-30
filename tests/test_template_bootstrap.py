from __future__ import annotations

import importlib.util
import subprocess
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
    def __init__(self, cluster_status=None):
        self.calls = []
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
                    "avail": 9876543210,
                    "shared": 0,
                }
            ]
        raise AssertionError(f"unexpected JSON command: {call!r}")

    def run(self, argv, check=True, timeout=120):
        del check, timeout
        call = tuple(argv)
        self.calls.append(call)
        if call[:2] == ("pvesm", "path"):
            probe_name = call[2].split("/", 1)[1]
            return subprocess.CompletedProcess(call, 0, f"/var/lib/vz/{probe_name}\n", "")
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


if __name__ == "__main__":
    unittest.main()

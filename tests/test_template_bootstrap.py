from __future__ import annotations

import importlib.util
import subprocess
import sys
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
sys.dont_write_bytecode = True
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


class OfficialImagePinningTest(unittest.TestCase):
    def test_all_images_use_reviewed_immutable_official_builds(self):
        catalog = BOOTSTRAP.load_catalog()
        expected = {
            "ubuntu-2204": (
                "ubuntu-22.04-server-cloudimg-amd64.img",
                "c0a5af17e6c0f76351fe07e2fffef3011dab1facb8a8ed5701dcf648dabd4f0a",
                "c0a5af17e6c0f76351fe07e2fffef3011dab1facb8a8ed5701dcf648dabd4f0a",
            ),
            "ubuntu-2404": (
                "ubuntu-24.04-server-cloudimg-amd64.img",
                "d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30",
                "d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30",
            ),
            "almalinux-8": (
                "AlmaLinux-8-GenericCloud-8.10-20260831.x86_64.qcow2",
                "66a440b458e0a0f774868f1b5d74433080c6718e40f38b59d05ff9ab269ae240",
                "66a440b458e0a0f774868f1b5d74433080c6718e40f38b59d05ff9ab269ae240",
            ),
            "debian-13": (
                "debian-13-generic-amd64-20260831-2587.qcow2",
                "ce793c5de15b3d7f2294e4d054a20dc5600751018c0d2e9682ffee2d5a580939",
                "5a069019420fb9441ad4f8004c661fadb747edd5662ca54a17c8f923dee7d717e21dbdaa4ba72d6fce7f920e0217f0a9af382298a7d46ed4bc9dc33ac19181b6",
            ),
            "debian-12": (
                "debian-12-generic-amd64-20260821-2577.qcow2",
                "5b3a3ebcf65bddee9a7eb666f47dee50745a269947929875bd72259bd27e26d8",
                "ee13344d530f70ca055d880e5c9b61e9af89874af02c5e2a5c26724461c79409e6d76db97c67ab222e71d03c3e33a738a8958fa5c497962f592258e9835cfcb0",
            ),
            "centos-stream-9": (
                "CentOS-Stream-GenericCloud-9-20260901.0.x86_64.qcow2",
                "96cd8355802bd6454f8df8363cc899660a7cd9becf0af947675835e945eb7155",
                "96cd8355802bd6454f8df8363cc899660a7cd9becf0af947675835e945eb7155",
            ),
            "centos-stream-10": (
                "CentOS-Stream-GenericCloud-10-20260901.0.x86_64.qcow2",
                "d33095d9bb4b3f5a168794b92f174e5e71c031210e63ef75bfd91d9d13a7de01",
                "d33095d9bb4b3f5a168794b92f174e5e71c031210e63ef75bfd91d9d13a7de01",
            ),
        }

        self.assertEqual(set(expected), {item["templateRef"] for item in catalog["items"]})
        for item in catalog["items"]:
            with self.subTest(template=item["templateRef"]):
                filename, sha256, upstream_checksum = expected[item["templateRef"]]
                spec = BOOTSTRAP.URL_SPECS[item["source"]["urlKey"]]
                self.assertEqual(spec["filename"], filename)
                self.assertNotIn("latest", spec["url"].lower())
                self.assertNotRegex(spec["url"], r"/release/")
                self.assertNotIn("latest", spec["checksumUrl"].lower())
                self.assertNotRegex(spec["checksumUrl"], r"/release/")
                self.assertEqual(item["source"]["sha256"], sha256)
                self.assertEqual(
                    item["source"]["upstreamChecksum"]["value"],
                    upstream_checksum,
                )


class TemplateQGAEligibilityTest(unittest.TestCase):
    class ConfigRunner:
        def __init__(self, config: str):
            self.config = config

        def run(self, argv, check=True, timeout=120):
            del check, timeout
            if tuple(argv) == ("qm", "config", "9000"):
                return subprocess.CompletedProcess(tuple(argv), 0, self.config, "")
            raise AssertionError(f"unexpected command: {argv!r}")

    def test_template_volume_requires_qga_package_build_attestation(self):
        runner = self.ConfigRunner(
            "template: 1\n"
            "tags: ppflight-cloudinit\n"
            "agent: enabled=1\n"
            "scsi0: local-lvm:vm-9000-disk-0\n"
        )

        self.assertIsNone(BOOTSTRAP._template_volume(runner, 9000))

    def test_template_volume_requires_pve_agent_device_too(self):
        runner = self.ConfigRunner(
            "template: 1\n"
            "tags: ppflight-cloudinit;ppflight-qga-preinstalled\n"
            "scsi0: local-lvm:vm-9000-disk-0\n"
        )

        self.assertIsNone(BOOTSTRAP._template_volume(runner, 9000))

    def test_template_volume_accepts_qga_preinstalled_template(self):
        runner = self.ConfigRunner(
            "template: 1\n"
            "tags: ppflight-cloudinit;ppflight-qga-preinstalled\n"
            "agent: enabled=1,fstrim_cloned_disks=1\n"
            "scsi0: local-lvm:vm-9000-disk-0,discard=on\n"
        )

        self.assertEqual(
            BOOTSTRAP._template_volume(runner, 9000),
            "local-lvm:vm-9000-disk-0",
        )


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

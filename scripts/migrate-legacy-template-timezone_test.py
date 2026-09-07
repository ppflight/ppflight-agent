#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("migrate-legacy-template-timezone.py")
SPEC = importlib.util.spec_from_file_location("ppflight_timezone_migration", SCRIPT)
assert SPEC and SPEC.loader
MIGRATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MIGRATOR
SPEC.loader.exec_module(MIGRATOR)


class LegacyTemplateTimezoneMigrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.configs = self.root / "qemu-server"
        self.snippets = self.root / "snippets"
        self.configs.mkdir()
        self.snippets.mkdir()
        MIGRATOR.CONFIG_DIR = self.configs
        self.original_run = MIGRATOR.run
        self.original_fchown = MIGRATOR.os.fchown
        MIGRATOR.os.fchown = lambda *_: None
        self.fail_set_vmid: int | None = None
        MIGRATOR.run = self.fake_run

    def tearDown(self) -> None:
        MIGRATOR.run = self.original_run
        MIGRATOR.os.fchown = self.original_fchown
        self.temporary.cleanup()

    def create_template(self, vmid: int, timezone: str = "UTC") -> tuple[Path, str]:
        content = (
            "#cloud-config\n"
            "disable_root: false\n"
            f"timezone: {timezone}\n"
            "ntp:\n"
            "  enabled: true\n"
        ).encode()
        digest = hashlib.sha256(content).hexdigest()
        name = f"ppflight-debian-{digest}.yaml"
        source = self.snippets / name
        source.write_bytes(content)
        volume = f"local:snippets/{name}"
        (self.configs / f"{vmid}.conf").write_text(
            f"template: 1\nname: ubuntu-2204\ncicustom: vendor={volume}\n",
            encoding="utf-8",
        )
        return source, volume

    def fake_run(self, *argv: str) -> str:
        if argv[:2] == ("pvesm", "path"):
            return str(self.snippets / argv[2].split("/", 1)[1]) + "\n"
        if argv[:2] == ("qm", "config"):
            return (self.configs / f"{argv[2]}.conf").read_text(encoding="utf-8")
        if argv[:2] == ("qm", "set"):
            vmid = int(argv[2])
            if vmid == self.fail_set_vmid:
                raise MIGRATOR.MigrationError("injected qm set failure")
            path = self.configs / f"{vmid}.conf"
            lines = path.read_text(encoding="utf-8").splitlines()
            replacement = argv[4]
            path.write_text(
                "\n".join(
                    f"cicustom: {replacement}" if line.startswith("cicustom: ") else line
                    for line in lines
                )
                + "\n",
                encoding="utf-8",
            )
            return ""
        raise AssertionError(argv)

    def test_migrates_without_changing_or_deleting_original(self) -> None:
        source, old_volume = self.create_template(9000)
        original = source.read_bytes()
        migrations, scanned = MIGRATOR.plan_migrations()
        self.assertEqual((scanned, len(migrations)), (1, 1))
        MIGRATOR.apply_migrations(migrations)

        config = (self.configs / "9000.conf").read_text(encoding="utf-8")
        self.assertNotIn(old_volume, config)
        self.assertNotIn(b"timezone:", migrations[0].new_path.read_bytes())
        self.assertEqual(source.read_bytes(), original)

        migrations, scanned = MIGRATOR.plan_migrations()
        self.assertEqual((scanned, len(migrations)), (1, 0))

    def test_hash_mismatch_fails_before_template_mutation(self) -> None:
        source, _ = self.create_template(9001)
        source.write_text("#cloud-config\ntimezone: UTC\ntampered: true\n", encoding="utf-8")
        before = (self.configs / "9001.conf").read_text(encoding="utf-8")
        with self.assertRaisesRegex(MIGRATOR.MigrationError, "hash mismatch"):
            MIGRATOR.plan_migrations()
        self.assertEqual((self.configs / "9001.conf").read_text(encoding="utf-8"), before)

    def test_rolls_back_prior_template_switch_when_later_switch_fails(self) -> None:
        _, first_volume = self.create_template(9002)
        _, second_volume = self.create_template(9003, "America/Los_Angeles")
        migrations, scanned = MIGRATOR.plan_migrations()
        self.assertEqual((scanned, len(migrations)), (2, 2))
        self.fail_set_vmid = 9003
        with self.assertRaisesRegex(MIGRATOR.MigrationError, "prior template switches rolled back"):
            MIGRATOR.apply_migrations(migrations)
        self.assertIn(first_volume, (self.configs / "9002.conf").read_text(encoding="utf-8"))
        self.assertIn(second_volume, (self.configs / "9003.conf").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

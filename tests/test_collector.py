"""Tests for directory collection, front matter parsing and vendor detection."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from netvault.collector import (
    CollectionError,
    collect_directory,
    detect_vendor,
    parse_config_file,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

CISCO_CONFIG = (
    "# device: core-sw-01\n"
    "# vendor: cisco-ios\n"
    "# site: porto-lab\n"
    "# role: core-switch\n"
    "\n"
    "!\n"
    "version 15.2\n"
    "hostname core-sw-01\n"
    "end\n"
)

CISCO_CONFIG_WITHOUT_HEADER = (
    "version 15.2\n"
    "hostname edge-rtr-02\n"
    "interface GigabitEthernet0/1\n"
    " description uplink\n"
    "line vty 0 4\n"
    " transport input ssh\n"
    "end\n"
)

ARUBA_CONFIG = (
    "Running configuration:\n"
    "\n"
    "; JL262A Configuration Editor; Created on release #WC.16.11.0002\n"
    "; Ver #14:1c\n"
    "\n"
    'hostname "sw-aruba-01"\n'
    "ip ssh\n"
    "no telnet-server\n"
    "spanning-tree\n"
)


def write_file(root: Path, relative: str, text: str) -> Path:
    """Write a UTF-8 fixture file below *root*."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class ParseConfigFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    def test_front_matter_metadata_is_parsed_and_stripped_from_body(self) -> None:
        path = write_file(self.root, "device.cfg", CISCO_CONFIG)
        config = parse_config_file(path, source="device.cfg")
        self.assertEqual(config.info.name, "core-sw-01")
        self.assertEqual(config.info.vendor, "cisco-ios")
        self.assertEqual(config.info.site, "porto-lab")
        self.assertEqual(config.info.role, "core-switch")
        self.assertEqual(config.source, "device.cfg")
        self.assertNotIn("# device:", config.content)
        self.assertTrue(config.content.lstrip().startswith("!"))

    def test_device_name_falls_back_to_filename(self) -> None:
        path = write_file(self.root, "edge-rtr-02.cfg", CISCO_CONFIG_WITHOUT_HEADER)
        config = parse_config_file(path)
        self.assertEqual(config.info.name, "edge-rtr-02")
        self.assertEqual(config.info.vendor, "cisco-ios")
        self.assertEqual(config.source, str(path))

    def test_vendor_aliases_in_front_matter_are_normalized(self) -> None:
        for alias, expected in (("IOS", "cisco-ios"), ("cisco_ios", "cisco-ios"), ("HP", "aruba")):
            with self.subTest(alias=alias):
                path = write_file(
                    self.root,
                    f"{alias}.cfg",
                    f"# vendor: {alias}\nhostname lab\nend\n",
                )
                config = parse_config_file(path)
                self.assertEqual(config.info.vendor, expected)

    def test_aruba_configuration_is_detected(self) -> None:
        path = write_file(self.root, "access-01.cfg", ARUBA_CONFIG)
        config = parse_config_file(path)
        self.assertEqual(config.info.name, "access-01")
        self.assertEqual(config.info.vendor, "aruba")

    def test_unknown_vendor_cannot_be_detected(self) -> None:
        path = write_file(self.root, "mystery.cfg", "hello\nworld\n")
        with self.assertRaises(CollectionError) as caught:
            parse_config_file(path)
        self.assertIn("cannot determine", str(caught.exception))

    def test_unsupported_explicit_vendor_is_rejected(self) -> None:
        path = write_file(
            self.root,
            "device.cfg",
            "# vendor: juniper\nhostname lab\nend\n",
        )
        with self.assertRaises(CollectionError) as caught:
            parse_config_file(path)
        self.assertIn("unsupported vendor", str(caught.exception))

    def test_configuration_without_body_is_rejected(self) -> None:
        path = write_file(
            self.root,
            "empty.cfg",
            "# device: core-sw-01\n# vendor: cisco-ios\n# site: porto-lab\n",
        )
        with self.assertRaises(CollectionError) as caught:
            parse_config_file(path)
        self.assertIn("no configuration content", str(caught.exception))

    def test_invalid_device_name_is_rejected(self) -> None:
        path = write_file(
            self.root,
            "device.cfg",
            "# device: bad name!\n# vendor: cisco-ios\nhostname x\nend\n",
        )
        with self.assertRaises(CollectionError) as caught:
            parse_config_file(path)
        self.assertIn("invalid device name", str(caught.exception))

    def test_duplicate_front_matter_key_is_rejected(self) -> None:
        path = write_file(
            self.root,
            "device.cfg",
            "# device: one\n# device: two\n# vendor: cisco-ios\nhostname x\nend\n",
        )
        with self.assertRaises(CollectionError) as caught:
            parse_config_file(path)
        self.assertIn("duplicate front matter key", str(caught.exception))

    def test_non_utf8_file_is_rejected(self) -> None:
        path = self.root / "binary.cfg"
        path.write_bytes(b"\xff\xfe\x00\x01not utf-8")
        with self.assertRaises(CollectionError) as caught:
            parse_config_file(path)
        self.assertIn("UTF-8", str(caught.exception))

    def test_front_matter_stops_at_first_content_line(self) -> None:
        path = write_file(
            self.root,
            "device.cfg",
            "# vendor: cisco-ios\nhostname r1\n# this comment stays in the body\nend\n",
        )
        config = parse_config_file(path)
        self.assertIn("# this comment stays in the body", config.content)
        self.assertEqual(config.info.name, "device")


class DetectVendorTest(unittest.TestCase):
    def test_cisco_configuration_is_detected(self) -> None:
        self.assertEqual(detect_vendor(CISCO_CONFIG_WITHOUT_HEADER), "cisco-ios")

    def test_aruba_configuration_is_detected(self) -> None:
        self.assertEqual(detect_vendor(ARUBA_CONFIG), "aruba")

    def test_ambiguous_configuration_returns_none(self) -> None:
        self.assertIsNone(detect_vendor("hostname lab\n"))


class CollectDirectoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    def test_directory_is_scanned_recursively_in_sorted_order(self) -> None:
        write_file(self.root, "site-b/edge-rtr-02.cfg", CISCO_CONFIG_WITHOUT_HEADER)
        write_file(
            self.root,
            "site-a/core.cfg",
            CISCO_CONFIG.replace("core-sw-01", "core-a").replace(
                "porto-lab", "lab-a"
            ),
        )
        result = collect_directory(self.root)
        self.assertEqual(result.issues, ())
        self.assertEqual(
            [config.source for config in result.configs],
            ["site-a/core.cfg", "site-b/edge-rtr-02.cfg"],
        )
        self.assertEqual(
            [config.info.name for config in result.configs],
            ["core-a", "edge-rtr-02"],
        )

    def test_hidden_paths_and_unsupported_files_are_ignored(self) -> None:
        write_file(self.root, ".hidden/hidden.cfg", CISCO_CONFIG)
        write_file(self.root, "notes.md", "just notes")
        write_file(self.root, "visible.cfg", CISCO_CONFIG.replace("core-sw-01", "visible"))
        result = collect_directory(self.root)
        self.assertEqual(len(result.configs), 1)
        self.assertEqual(result.configs[0].info.name, "visible")

    def test_bad_files_are_reported_while_good_files_are_collected(self) -> None:
        write_file(self.root, "good.cfg", CISCO_CONFIG)
        write_file(self.root, "bad.cfg", "this is not a network configuration\n")
        result = collect_directory(self.root)
        self.assertEqual(len(result.configs), 1)
        self.assertEqual(len(result.issues), 1)
        self.assertEqual(result.issues[0].source, "bad.cfg")
        self.assertIn("cannot determine", result.issues[0].message)

    def test_duplicate_device_names_are_reported_and_skipped(self) -> None:
        write_file(self.root, "first.cfg", CISCO_CONFIG)
        write_file(self.root, "second.cfg", CISCO_CONFIG)
        result = collect_directory(self.root)
        self.assertEqual(len(result.configs), 1)
        self.assertEqual(result.configs[0].source, "first.cfg")
        self.assertEqual(len(result.issues), 1)
        self.assertIn("duplicate device name", result.issues[0].message)

    def test_missing_directory_raises(self) -> None:
        with self.assertRaises(CollectionError):
            collect_directory(self.root / "does-not-exist")

    def test_empty_directory_returns_empty_result(self) -> None:
        result = collect_directory(self.root)
        self.assertEqual(result.configs, ())
        self.assertEqual(result.issues, ())

    def test_repository_example_configs_are_valid(self) -> None:
        baseline = REPO_ROOT / "examples" / "lab-configs" / "baseline"
        self.assertTrue(baseline.is_dir(), f"missing example directory: {baseline}")
        result = collect_directory(baseline)
        self.assertEqual(result.issues, ())
        self.assertEqual(
            {config.info.name for config in result.configs},
            {"core-sw-01", "edge-rtr-01", "access-aruba-01"},
        )
        vendors = {config.info.name: config.info.vendor for config in result.configs}
        self.assertEqual(vendors["core-sw-01"], "cisco-ios")
        self.assertEqual(vendors["edge-rtr-01"], "cisco-ios")
        self.assertEqual(vendors["access-aruba-01"], "aruba")


if __name__ == "__main__":
    unittest.main()

"""Tests for unified and semantic configuration diffing."""

from __future__ import annotations

import unittest

from netvault.diffing import (
    InterfaceChanges,
    build_diff,
    extract_interfaces,
    unified_diff_text,
)

CISCO_CONFIG = (
    "hostname core-sw-01\n"
    "!\n"
    "interface GigabitEthernet0/1\n"
    " description uplink\n"
    " switchport mode trunk\n"
    "!\n"
    "interface GigabitEthernet0/2\n"
    " description spare\n"
    " shutdown\n"
    "!\n"
    "ip route 0.0.0.0 0.0.0.0 198.51.100.1\n"
)

ARUBA_CONFIG = (
    'hostname "sw1"\n'
    "vlan 10\n"
    '   name "MGMT"\n'
    "   exit\n"
    "interface 1\n"
    '   name "uplink"\n'
    "   exit\n"
    "interface 24\n"
    '   name "lab"\n'
    "   exit\n"
)


def make_diff(old: str, new: str, context: int = 3):
    """Build a diff result for the given fixtures."""
    return build_diff(
        device="core-sw-01",
        old_text=old,
        new_text=new,
        from_revision=1,
        to_revision=2,
        from_digest="a" * 64,
        to_digest="b" * 64,
        from_captured_at="2026-01-01T00:00:00Z",
        to_captured_at="2026-01-02T00:00:00Z",
        context=context,
    )


class ExtractInterfacesTest(unittest.TestCase):
    def test_cisco_interface_blocks_are_extracted(self) -> None:
        blocks = extract_interfaces(CISCO_CONFIG)
        self.assertEqual(
            set(blocks),
            {"GigabitEthernet0/1", "GigabitEthernet0/2"},
        )
        self.assertIn("description uplink", blocks["GigabitEthernet0/1"])
        self.assertIn("shutdown", blocks["GigabitEthernet0/2"])
        self.assertNotIn("!", blocks["GigabitEthernet0/2"])

    def test_aruba_numeric_interface_blocks_are_extracted(self) -> None:
        blocks = extract_interfaces(ARUBA_CONFIG)
        self.assertEqual(set(blocks), {"1", "24"})
        self.assertIn('name "uplink"', blocks["1"])

    def test_top_level_commands_end_a_block(self) -> None:
        blocks = extract_interfaces(
            "interface Loopback0\n description mgmt\nip route 0.0.0.0 0.0.0.0 192.0.2.1\n"
        )
        self.assertEqual(set(blocks), {"Loopback0"})
        self.assertNotIn("ip route", blocks["Loopback0"])

    def test_configuration_without_interfaces_returns_empty_mapping(self) -> None:
        self.assertEqual(extract_interfaces("hostname r1\nend\n"), {})


class UnifiedDiffTest(unittest.TestCase):
    def test_unified_diff_has_file_headers_and_hunks(self) -> None:
        diff = unified_diff_text(
            "hostname r1\nntp server 203.0.113.10\n",
            "hostname r1\nntp server 203.0.113.11\n",
            device="core-sw-01",
            from_revision=1,
            to_revision=2,
            from_digest="a" * 64,
            to_digest="b" * 64,
            from_captured_at="2026-01-01T00:00:00Z",
            to_captured_at="2026-01-02T00:00:00Z",
        )
        self.assertIn("--- core-sw-01 revision 1", diff)
        self.assertIn("+++ core-sw-01 revision 2", diff)
        self.assertIn("2026-01-01T00:00:00Z", diff)
        self.assertIn("digest aaaaaaaaaaaa", diff)
        self.assertIn("@@", diff)
        self.assertIn("-ntp server 203.0.113.10", diff)
        self.assertIn("+ntp server 203.0.113.11", diff)

    def test_identical_configurations_produce_no_unified_diff(self) -> None:
        result = make_diff(CISCO_CONFIG, CISCO_CONFIG)
        self.assertEqual(result.unified, "")
        self.assertFalse(result.summary.changed)
        self.assertEqual(result.summary.lines_added, 0)
        self.assertEqual(result.summary.lines_removed, 0)
        self.assertEqual(result.summary.render_text(), "No changes between revision 1 and revision 2.")

    def test_context_parameter_controls_unified_context_lines(self) -> None:
        old = "a\nb\nc\nd\ne\nf\ng\nh\n"
        new = "a\nb\nc\nd\nE\nf\ng\nh\n"
        wide = make_diff(old, new, context=3).unified
        narrow = make_diff(old, new, context=0).unified
        wide_context = [line for line in wide.splitlines() if line.startswith(" ")]
        narrow_context = [line for line in narrow.splitlines() if line.startswith(" ")]
        self.assertEqual(narrow_context, [])
        self.assertGreater(len(wide_context), 0)


class SemanticDiffTest(unittest.TestCase):
    def test_line_and_size_counts(self) -> None:
        old = "hostname r1\nntp server 203.0.113.10\nend\n"
        new = "hostname r1\nntp server 203.0.113.11\nlogging host 203.0.113.20\nend\n"
        result = make_diff(old, new)
        summary = result.summary
        self.assertEqual(summary.lines_added, 2)
        self.assertEqual(summary.lines_removed, 1)
        self.assertEqual(summary.line_count_delta, 1)
        self.assertEqual(
            summary.size_delta,
            len(new.encode("utf-8")) - len(old.encode("utf-8")),
        )
        self.assertTrue(summary.changed)

    def test_interfaces_added_removed_and_modified(self) -> None:
        old = (
            "interface GigabitEthernet0/1\n"
            " description uplink\n"
            "!\n"
            "interface GigabitEthernet0/2\n"
            " description spare\n"
            " shutdown\n"
            "!\n"
        )
        new = (
            "interface GigabitEthernet0/1\n"
            " description uplink-to-edge\n"
            "!\n"
            "interface GigabitEthernet0/3\n"
            " description new-port\n"
            " shutdown\n"
            "!\n"
        )
        summary = make_diff(old, new).summary
        self.assertEqual(
            summary.interfaces,
            InterfaceChanges(
                added=("GigabitEthernet0/3",),
                removed=("GigabitEthernet0/2",),
                modified=("GigabitEthernet0/1",),
            ),
        )

    def test_acl_and_route_lines_are_counted(self) -> None:
        old = "hostname r1\n"
        new = (
            "hostname r1\n"
            "ip access-list extended LAB\n"
            " permit tcp any any eq 22\n"
            " deny ip any any log\n"
            "ip route 0.0.0.0 0.0.0.0 198.51.100.1\n"
        )
        summary = make_diff(old, new).summary
        self.assertEqual(summary.acl_lines_added, 3)
        self.assertEqual(summary.acl_lines_removed, 0)
        self.assertEqual(summary.route_lines_added, 1)
        self.assertEqual(summary.route_lines_removed, 0)

    def test_removed_acl_lines_are_counted(self) -> None:
        old = (
            "hostname r1\n"
            "ip access-list extended LAB\n"
            " permit tcp any any eq 22\n"
            " deny ip any any log\n"
        )
        new = "hostname r1\n"
        summary = make_diff(old, new).summary
        self.assertEqual(summary.acl_lines_removed, 3)
        self.assertEqual(summary.acl_lines_added, 0)

    def test_summary_text_contains_operator_markers(self) -> None:
        old = (
            "interface GigabitEthernet0/1\n"
            " description uplink\n"
            "!\n"
            "ip access-list extended LAB\n"
            " permit tcp any any eq 22\n"
        )
        new = (
            "interface GigabitEthernet0/1\n"
            " description uplink-to-edge\n"
            "!\n"
            "ip access-list extended LAB\n"
            " permit tcp any any eq 22\n"
            " deny ip any any log\n"
            "ip route 0.0.0.0 0.0.0.0 198.51.100.1\n"
        )
        text = make_diff(old, new).summary.render_text()
        self.assertIn("Change summary - core-sw-01 (revision 1 -> 2)", text)
        self.assertIn("lines: +3 / -1 (net +2)", text)
        self.assertIn("size: +", text)
        self.assertIn("interfaces added: none", text)
        self.assertIn("interfaces modified: GigabitEthernet0/1", text)
        self.assertIn("ACL lines: +1 / -0", text)
        self.assertIn("route lines: +1 / -0", text)

    def test_diff_result_carries_revision_identity(self) -> None:
        result = make_diff("a\n", "b\n")
        self.assertEqual(result.summary.device, "core-sw-01")
        self.assertEqual(result.summary.from_revision, 1)
        self.assertEqual(result.summary.to_revision, 2)
        self.assertEqual(result.summary.from_digest, "a" * 64)
        self.assertEqual(result.summary.to_digest, "b" * 64)
        self.assertEqual(result.summary.from_captured_at, "2026-01-01T00:00:00Z")
        self.assertEqual(result.summary.to_captured_at, "2026-01-02T00:00:00Z")


if __name__ == "__main__":
    unittest.main()

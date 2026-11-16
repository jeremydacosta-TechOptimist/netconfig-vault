"""Tests for configuration normalization and content hashing."""

from __future__ import annotations

import hashlib
import unittest

from netvault.normalize import content_digest, digest_normalized, normalize_config


class NormalizeConfigTest(unittest.TestCase):
    def test_empty_and_whitespace_only_input_return_empty_string(self) -> None:
        for value in ("", "   ", "\r\n\r\n", "\n \n\t\n"):
            with self.subTest(value=value):
                self.assertEqual(normalize_config(value), "")

    def test_crlf_and_cr_line_endings_are_unified(self) -> None:
        self.assertEqual(normalize_config("a\r\nb\rc"), "a\nb\nc\n")

    def test_trailing_whitespace_is_removed_but_indentation_is_kept(self) -> None:
        text = "interface GigabitEthernet0/1   \n description uplink \t\n"
        self.assertEqual(
            normalize_config(text),
            "interface GigabitEthernet0/1\n description uplink\n",
        )

    def test_cisco_volatile_header_lines_are_dropped(self) -> None:
        text = (
            "! Last configuration change at 10:00:00 UTC Mon Nov 16 2026\n"
            "! NVRAM config last updated at 10:00:01 UTC Mon Nov 16 2026\n"
            "! No configuration change since last restart\n"
            "Building configuration...\n"
            "Current configuration : 1234 bytes\n"
            "hostname r1\n"
            "ntp clock-period 17179869\n"
            "end\n"
        )
        self.assertEqual(normalize_config(text), "hostname r1\nend\n")

    def test_aruba_volatile_header_lines_are_dropped(self) -> None:
        text = (
            "Running configuration:\n\n"
            "; JL262A Configuration Editor; Created on release #WC.16.11.0002\n"
            "; Ver #14:1c.6f.4f.67\n"
            'hostname "sw1"\n'
        )
        self.assertEqual(normalize_config(text), 'hostname "sw1"\n')

    def test_blank_runs_are_collapsed_and_edges_trimmed(self) -> None:
        text = "\n\nhostname r1\n\n\n\ndescription x\n\n"
        self.assertEqual(normalize_config(text), "hostname r1\n\ndescription x\n")

    def test_normalization_is_idempotent(self) -> None:
        text = (
            "\r\n! Last configuration change at now\r\n"
            "hostname  r1  \r\n\r\n\r\n"
            "interface GigabitEthernet0/1\r\n description x\r\n"
        )
        once = normalize_config(text)
        self.assertEqual(normalize_config(once), once)

    def test_normalized_output_ends_with_exactly_one_newline(self) -> None:
        normalized = normalize_config("hostname r1")
        self.assertTrue(normalized.endswith("\n"))
        self.assertFalse(normalized.endswith("\n\n"))


class ContentDigestTest(unittest.TestCase):
    def test_digest_matches_sha256_of_normalized_text(self) -> None:
        text = "hostname r1\r\ninterface GigabitEthernet0/1\r\n description uplink \r\n"
        expected = hashlib.sha256(normalize_config(text).encode("utf-8")).hexdigest()
        self.assertEqual(content_digest(text), expected)
        self.assertEqual(len(content_digest(text)), 64)

    def test_digest_ignores_volatile_lines_and_line_endings(self) -> None:
        first = "hostname r1\n! Last configuration change at 10:00:00 UTC\nend\n"
        second = "hostname r1\r\nend\r\n"
        self.assertEqual(content_digest(first), content_digest(second))

    def test_digest_changes_when_configuration_changes(self) -> None:
        self.assertNotEqual(content_digest("hostname r1\n"), content_digest("hostname r2\n"))

    def test_digest_normalized_matches_content_digest_of_normalized_text(self) -> None:
        normalized = normalize_config("hostname r1\n")
        self.assertEqual(digest_normalized(normalized), content_digest(normalized))

    def test_same_content_produces_stable_digest(self) -> None:
        self.assertEqual(content_digest("hostname r1\n"), content_digest("hostname r1\n"))


if __name__ == "__main__":
    unittest.main()

"""Tests for the content-addressed snapshot store."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from netvault.models import DeviceInfo
from netvault.normalize import normalize_config
from netvault.store import (
    NotInitializedError,
    UnknownDeviceError,
    UnknownRevisionError,
    Vault,
    VaultError,
)

CONFIG_V1 = (
    "hostname core-sw-01\n"
    "interface GigabitEthernet0/1\n"
    " description uplink\n"
    "end\n"
)
CONFIG_V2 = CONFIG_V1.replace(" description uplink", " description uplink-to-edge")


def device(name: str = "core-sw-01", site: str = "porto-lab") -> DeviceInfo:
    """Build the device metadata used by the store tests."""
    return DeviceInfo(name=name, vendor="cisco-ios", site=site)


class VaultLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name) / "vault"

    def test_initialize_creates_index_and_object_directory(self) -> None:
        vault = Vault.initialize(self.root)
        self.assertTrue(vault.db_path.is_file())
        self.assertTrue(vault.objects_dir.is_dir())
        self.assertEqual(vault.stats().devices, 0)
        self.assertIsNotNone(Vault.open(self.root))

    def test_initialize_is_idempotent(self) -> None:
        Vault.initialize(self.root).snapshot(device(), CONFIG_V1)
        vault = Vault.initialize(self.root)
        self.assertEqual(vault.stats().devices, 1)
        self.assertEqual(vault.list_devices()[0].revisions, 1)

    def test_initialize_rejects_a_file_path(self) -> None:
        file_path = Path(self._temporary.name) / "not-a-directory"
        file_path.write_text("x", encoding="utf-8")
        with self.assertRaises(VaultError):
            Vault.initialize(file_path)

    def test_open_uninitialized_vault_raises(self) -> None:
        with self.assertRaises(NotInitializedError) as caught:
            Vault.open(self.root)
        self.assertIn("netvault init", str(caught.exception))

    def test_open_rejects_a_directory_without_vault_schema(self) -> None:
        self.root.mkdir(parents=True)
        (self.root / "vault.db").write_bytes(b"")
        with self.assertRaises(NotInitializedError):
            Vault.open(self.root)

    def test_open_rejects_directory_that_is_not_a_database(self) -> None:
        self.root.mkdir(parents=True)
        (self.root / "vault.db").write_text("not a database", encoding="utf-8")
        with self.assertRaises(NotInitializedError):
            Vault.open(self.root)

    def test_reopened_vault_keeps_devices_and_history(self) -> None:
        Vault.initialize(self.root).snapshot(device(), CONFIG_V1)
        reopened = Vault.open(self.root)
        self.assertEqual(reopened.list_devices()[0].name, "core-sw-01")
        self.assertEqual(reopened.history("core-sw-01")[0].revision, 1)


class SnapshotStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name) / "vault"
        self.vault = Vault.initialize(self.root)

    def test_first_snapshot_creates_revision_blob_and_digest(self) -> None:
        outcome = self.vault.snapshot(device(), CONFIG_V1)
        record = outcome.record
        self.assertTrue(outcome.created)
        self.assertEqual(record.revision, 1)
        self.assertEqual(record.device, "core-sw-01")
        self.assertEqual(record.vendor, "cisco-ios")
        self.assertEqual(len(record.digest), 64)
        self.assertEqual(
            record.digest,
            hashlib.sha256(normalize_config(CONFIG_V1).encode("utf-8")).hexdigest(),
        )
        blob_path = self.vault.objects_dir / record.digest[:2] / record.digest
        self.assertTrue(blob_path.is_file())
        self.assertEqual(self.vault.read_content(record.digest), normalize_config(CONFIG_V1))
        stats = self.vault.stats()
        self.assertEqual((stats.devices, stats.snapshots, stats.blobs), (1, 1, 1))

    def test_identical_snapshot_is_deduplicated(self) -> None:
        first = self.vault.snapshot(device(), CONFIG_V1, note="initial")
        second = self.vault.snapshot(device(), CONFIG_V1, note="later note")
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertEqual(second.record.revision, first.record.revision)
        self.assertEqual(second.record.digest, first.record.digest)
        self.assertEqual(second.record.note, "initial")
        stats = self.vault.stats()
        self.assertEqual((stats.snapshots, stats.blobs), (1, 1))
        self.assertEqual(len(self.vault.history("core-sw-01")), 1)

    def test_changed_content_creates_the_next_revision(self) -> None:
        self.vault.snapshot(device(), CONFIG_V1)
        outcome = self.vault.snapshot(device(), CONFIG_V2)
        self.assertTrue(outcome.created)
        self.assertEqual(outcome.record.revision, 2)
        history = self.vault.history("core-sw-01")
        self.assertEqual([record.revision for record in history], [1, 2])
        self.assertEqual(self.vault.stats().blobs, 2)

    def test_revision_numbers_increment_from_one(self) -> None:
        for index in range(3):
            self.vault.snapshot(device(), CONFIG_V1 + f"! change {index}\n")
        history = self.vault.history("core-sw-01")
        self.assertEqual([record.revision for record in history], [1, 2, 3])

    def test_history_is_ordered_by_revision_even_with_odd_timestamps(self) -> None:
        timestamps = [
            "2026-01-03T00:00:00Z",
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
        ]
        for index, timestamp in enumerate(timestamps):
            self.vault.snapshot(
                device(), CONFIG_V1 + f"! change {index}\n", captured_at=timestamp
            )
        history = self.vault.history("core-sw-01")
        self.assertEqual([record.revision for record in history], [1, 2, 3])
        self.assertEqual([record.captured_at for record in history], timestamps)

    def test_blob_is_shared_between_devices_with_identical_content(self) -> None:
        first = self.vault.snapshot(device("core-sw-01"), CONFIG_V1)
        second = self.vault.snapshot(device("core-sw-02"), CONFIG_V1)
        self.assertEqual(first.record.digest, second.record.digest)
        self.assertEqual(first.record.revision, 1)
        self.assertEqual(second.record.revision, 1)
        stats = self.vault.stats()
        self.assertEqual((stats.devices, stats.snapshots, stats.blobs), (2, 2, 1))

    def test_note_and_source_name_are_stored(self) -> None:
        self.vault.snapshot(
            device(),
            CONFIG_V1,
            captured_at="2026-01-31T09:30:00Z",
            note="before change window 42",
            source_name="site-a/core-sw-01.cfg",
        )
        record = self.vault.history("core-sw-01")[0]
        self.assertEqual(record.note, "before change window 42")
        self.assertEqual(record.source_name, "site-a/core-sw-01.cfg")
        self.assertEqual(record.captured_at, "2026-01-31T09:30:00Z")

    def test_latest_snapshot_returns_the_highest_revision(self) -> None:
        self.vault.snapshot(device(), CONFIG_V1, captured_at="2026-01-01T00:00:00Z")
        self.vault.snapshot(device(), CONFIG_V2, captured_at="2026-01-02T00:00:00Z")
        latest = self.vault.latest_snapshot("core-sw-01")
        self.assertEqual(latest.revision, 2)
        self.assertEqual(latest.captured_at, "2026-01-02T00:00:00Z")

    def test_get_snapshot_returns_one_revision(self) -> None:
        self.vault.snapshot(device(), CONFIG_V1)
        self.vault.snapshot(device(), CONFIG_V2)
        record = self.vault.get_snapshot("core-sw-01", 1)
        self.assertEqual(record.revision, 1)
        self.assertEqual(self.vault.read_content(record.digest), normalize_config(CONFIG_V1))

    def test_read_revision_returns_record_and_content(self) -> None:
        self.vault.snapshot(device(), CONFIG_V1)
        record, content = self.vault.read_revision("core-sw-01", 1)
        self.assertEqual(record.revision, 1)
        self.assertEqual(content, normalize_config(CONFIG_V1))

    def test_unknown_device_raises(self) -> None:
        for operation in (
            lambda: self.vault.history("nope"),
            lambda: self.vault.get_snapshot("nope", 1),
            lambda: self.vault.latest_snapshot("nope"),
            lambda: self.vault.read_revision("nope", 1),
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(UnknownDeviceError):
                    operation()

    def test_unknown_revision_raises(self) -> None:
        self.vault.snapshot(device(), CONFIG_V1)
        with self.assertRaises(UnknownRevisionError):
            self.vault.get_snapshot("core-sw-01", 99)

    def test_unknown_blob_raises(self) -> None:
        with self.assertRaises(VaultError):
            self.vault.read_content("0" * 64)

    def test_empty_configuration_is_rejected(self) -> None:
        with self.assertRaises(VaultError) as caught:
            self.vault.snapshot(device(), "   \n\n")
        self.assertIn("empty configuration", str(caught.exception))

    def test_malformed_timestamp_is_rejected(self) -> None:
        with self.assertRaises(VaultError):
            self.vault.snapshot(device(), CONFIG_V1, captured_at="yesterday")

    def test_device_metadata_is_refreshed_by_later_snapshots(self) -> None:
        self.vault.snapshot(device(site="porto-lab"), CONFIG_V1)
        self.vault.snapshot(device(site="lisbon-lab"), CONFIG_V2)
        summary = self.vault.list_devices()[0]
        self.assertEqual(summary.site, "lisbon-lab")
        self.assertEqual(summary.revisions, 2)

    def test_empty_metadata_in_later_snapshot_does_not_erase_known_site(self) -> None:
        self.vault.snapshot(device(site="porto-lab"), CONFIG_V1)
        self.vault.snapshot(device(site=""), CONFIG_V2)
        self.assertEqual(self.vault.list_devices()[0].site, "porto-lab")

    def test_device_lookup_is_case_insensitive(self) -> None:
        self.vault.snapshot(DeviceInfo(name="Core-SW-01", vendor="cisco-ios"), CONFIG_V1)
        self.vault.snapshot(DeviceInfo(name="core-sw-01", vendor="cisco-ios"), CONFIG_V2)
        summaries = self.vault.list_devices()
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0].revisions, 2)
        self.assertEqual(len(self.vault.history("CORE-sw-01")), 2)

    def test_list_devices_reports_latest_revision_metadata(self) -> None:
        self.vault.snapshot(device(), CONFIG_V1, captured_at="2026-01-01T00:00:00Z")
        self.vault.snapshot(device(), CONFIG_V2, captured_at="2026-01-02T00:00:00Z")
        summary = self.vault.list_devices()[0]
        self.assertEqual(summary.latest_revision, 2)
        self.assertEqual(summary.latest_captured_at, "2026-01-02T00:00:00Z")
        self.assertEqual(
            summary.latest_digest,
            hashlib.sha256(normalize_config(CONFIG_V2).encode("utf-8")).hexdigest(),
        )

    def test_stats_reports_stored_configuration_bytes(self) -> None:
        self.vault.snapshot(device("core-sw-01"), CONFIG_V1)
        self.vault.snapshot(device("core-sw-02"), CONFIG_V1)
        self.vault.snapshot(device("core-sw-01"), CONFIG_V2)
        expected_bytes = len(normalize_config(CONFIG_V1).encode("utf-8")) + len(
            normalize_config(CONFIG_V2).encode("utf-8")
        )
        stats = self.vault.stats()
        self.assertEqual(stats.config_bytes, expected_bytes)
        self.assertEqual(stats.blobs, 2)
        self.assertEqual(stats.snapshots, 3)

    def test_snapshots_are_append_only_and_never_rewritten(self) -> None:
        first = self.vault.snapshot(device(), CONFIG_V1, captured_at="2026-01-01T00:00:00Z")
        blob_path = self.vault.objects_dir / first.record.digest[:2] / first.record.digest
        content_before = blob_path.read_bytes()
        self.vault.snapshot(device(), CONFIG_V2)
        self.assertEqual(blob_path.read_bytes(), content_before)
        self.assertEqual(self.vault.history("core-sw-01")[0].captured_at, "2026-01-01T00:00:00Z")

    def test_duplicate_content_can_be_forced_into_a_new_revision(self) -> None:
        self.vault.snapshot(device(), CONFIG_V1)
        outcome = self.vault.snapshot(device(), CONFIG_V1, dedupe=False)
        self.assertTrue(outcome.created)
        self.assertEqual(outcome.record.revision, 2)
        self.assertEqual(self.vault.stats().blobs, 1)


if __name__ == "__main__":
    unittest.main()

"""Tests for the TLS13-PQ configuration plane."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from tls13pq import config as tls

EXAMPLE = Path(__file__).resolve().parent.parent / "example.json"


class DefaultProfileTests(unittest.TestCase):
    def test_default_hybrid_validates(self) -> None:
        tls.validate(tls.default_hybrid())

    def test_example_json_loads_and_validates(self) -> None:
        cfg = tls.load_config(EXAMPLE)
        self.assertTrue(cfg.groups.require_pq)
        self.assertIs(cfg.early_data.mode, tls.EarlyDataMode.COMMITTED)
        self.assertIs(cfg.replay.fail_mode, tls.FailMode.CLOSED)
        self.assertEqual(cfg.early_data.max_lifetime, timedelta(seconds=10))
        self.assertEqual(cfg.ech.key_ttl, timedelta(hours=24))

    def test_round_trip(self) -> None:
        original = tls.default_hybrid()
        restored = tls.from_dict(tls.to_dict(original))
        tls.validate(restored)
        self.assertIs(restored.groups.offered[0], tls.Group.X25519_MLKEM768)
        self.assertIs(restored.auth.schemes[0], tls.SigScheme.ML_DSA_65)
        self.assertEqual(restored.early_data.max_lifetime,
                         original.early_data.max_lifetime)

    def test_duration_variants(self) -> None:
        cfg = tls.default_hybrid()
        cfg.early_data.max_lifetime = timedelta(seconds=90)
        cfg.replay.window = timedelta(minutes=2)
        tls.validate(cfg)
        data = tls.to_dict(cfg)
        self.assertEqual(data["early_data"]["max_lifetime"], "1m30s")

    def test_numeric_duration_is_seconds(self) -> None:
        data = tls.to_dict(tls.default_hybrid())
        data["early_data"]["max_lifetime"] = 10  # 10 seconds, not 10 ns
        cfg = tls.from_dict(data)
        self.assertEqual(cfg.early_data.max_lifetime, timedelta(seconds=10))


class RejectionTests(unittest.TestCase):
    def test_rejects_fail_open_replay_filter(self) -> None:
        cfg = tls.default_hybrid()
        cfg.replay.fail_mode = "open"  # type: ignore[assignment]
        with self.assertRaises(tls.ConfigError):
            tls.validate(cfg)

    def test_committed_mode_needs_linearizable_store(self) -> None:
        cfg = tls.default_hybrid()
        cfg.commit.linearizable = False
        with self.assertRaises(tls.ConfigError):
            tls.validate(cfg)

    def test_committed_mode_needs_store(self) -> None:
        cfg = tls.default_hybrid()
        cfg.commit.store = ""
        with self.assertRaises(tls.ConfigError):
            tls.validate(cfg)

    def test_pure_pq_requires_opt_in(self) -> None:
        cfg = tls.default_hybrid()
        cfg.groups.offered = [tls.Group.MLKEM768]
        cfg.groups.allow_pure_pq = False
        with self.assertRaises(tls.ConfigError):
            tls.validate(cfg)

    def test_strict_pq_requires_pq_authentication(self) -> None:
        cfg = tls.default_hybrid()
        cfg.profile = tls.Profile.STRICT_PQ
        cfg.auth.require_pq_signature = False
        with self.assertRaises(tls.ConfigError):
            tls.validate(cfg)

    def test_replay_window_must_cover_ticket_lifetime(self) -> None:
        cfg = tls.default_hybrid()
        cfg.replay.window = cfg.early_data.max_lifetime - timedelta(microseconds=1)
        with self.assertRaises(tls.ConfigError):
            tls.validate(cfg)

    def test_padding_classes_must_be_strictly_increasing(self) -> None:
        cfg = tls.default_hybrid()
        cfg.padding.classes = [2816, 1400]
        with self.assertRaises(tls.ConfigError):
            tls.validate(cfg)

    def test_unknown_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps({
                "profile": "hybrid",
                "replay": {"failmode": "open"},
            }), encoding="utf-8")
            with self.assertRaises(tls.ConfigError):
                tls.load_config(path)

    def test_unknown_enum_label_is_rejected(self) -> None:
        data = tls.to_dict(tls.default_hybrid())
        data["groups"]["offered"] = ["X25519Kyber768Draft00"]
        with self.assertRaises(tls.ConfigError):
            tls.from_dict(data)


class CodepointTests(unittest.TestCase):
    def test_group_labels_and_codepoints(self) -> None:
        self.assertEqual(tls.Group.X25519_MLKEM768, 0x11EC)
        self.assertEqual(tls.Group.X25519_MLKEM768.label, "X25519MLKEM768")
        self.assertTrue(tls.Group.X25519_MLKEM768.is_hybrid)
        self.assertFalse(tls.Group.MLKEM768.is_hybrid)
        self.assertTrue(tls.Group.MLKEM768.is_post_quantum)

    def test_sig_scheme_labels(self) -> None:
        self.assertEqual(tls.SigScheme.ML_DSA_65, 0x0905)
        self.assertEqual(tls.SigScheme.ML_DSA_65.label, "ML-DSA-65")
        self.assertTrue(tls.SigScheme.ML_DSA_87.is_post_quantum)
        self.assertFalse(tls.SigScheme.ECDSA_P256.is_post_quantum)


if __name__ == "__main__":
    unittest.main()

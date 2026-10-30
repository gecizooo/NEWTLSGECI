"""Tests for the padding schedule and the handshake simulator."""

from __future__ import annotations

import unittest

from tls13pq.config import Group, Profile, default_hybrid
from tls13pq.early_data import EarlyDataStatus
from tls13pq.handshake import ClientHello, HandshakeSimulator, ServerState, demo_ticket
from tls13pq.padding import estimate_client_hello, pad_to_class, segments

CLASSES = [1400, 2816, 4224, 7040]


class PaddingTests(unittest.TestCase):
    def test_pad_to_class(self) -> None:
        self.assertEqual(pad_to_class(1400, CLASSES), 1400)
        self.assertEqual(pad_to_class(1401, CLASSES), 2816)
        self.assertEqual(pad_to_class(7041, CLASSES), 14080)

    def test_segments(self) -> None:
        self.assertEqual(segments(1400), 1)
        self.assertEqual(segments(2816), 2)
        self.assertEqual(segments(4224), 3)

    def test_classical_ech_stays_in_one_segment(self) -> None:
        est = estimate_client_hello(Group.X25519, 15, ech=True,
                                    early_data=False, classes=CLASSES)
        self.assertEqual(est.outer_padded, 1400)
        self.assertEqual(est.segments, 1)

    def test_hybrid_ech_needs_two_segments(self) -> None:
        est = estimate_client_hello(Group.X25519_MLKEM768, 15, ech=True,
                                    early_data=True, classes=CLASSES)
        self.assertEqual(est.outer_padded, 2816)
        self.assertEqual(est.segments, 2)

    def test_padding_hides_inner_length(self) -> None:
        short = estimate_client_hello(Group.X25519_MLKEM768, 5, ech=True,
                                      early_data=True, classes=CLASSES)
        long = estimate_client_hello(Group.X25519_MLKEM768, 40, ech=True,
                                     early_data=True, classes=CLASSES)
        self.assertEqual(short.outer_padded, long.outer_padded)
        self.assertEqual(short.segments, long.segments)

    def test_inner_fill_never_shorter_than_inner(self) -> None:
        for group in (Group.X25519, Group.X25519_MLKEM768, Group.X25519_MLKEM1024):
            est = estimate_client_hello(group, 30, ech=True,
                                        early_data=True, classes=CLASSES)
            self.assertGreaterEqual(est.inner_padded, est.inner)


class HandshakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = default_hybrid()
        self.sim = HandshakeSimulator(self.cfg)
        self.ticket = demo_ticket(self.sim.now)
        self.hello = ClientHello()

    def test_accept_path_publishes_one_effect(self) -> None:
        session = self.sim.process(self.hello, self.ticket)
        self.assertEqual(session.status, "0-rtt")
        self.assertIs(session.early_status, EarlyDataStatus.ACCEPTED)
        self.assertEqual(session.effects, 1)
        self.assertIn(ServerState.EARLY, session.states)
        self.assertIn(ServerState.COMMIT, session.states)
        self.assertEqual(len(self.sim.server.effects), 1)

    def test_ech_uses_inner_sni(self) -> None:
        session = self.sim.process(self.hello, self.ticket)
        self.assertIn(ServerState.ECH, session.states)
        self.assertTrue(any("inner SNI" in event for event in session.events))

    def test_replay_is_rejected_and_effect_count_stays_one(self) -> None:
        self.sim.process(self.hello, self.ticket)
        replay = self.sim.process(self.hello, self.ticket)
        self.assertIs(replay.early_status, EarlyDataStatus.REJECTED_REPLAY)
        self.assertEqual(replay.status, "1-rtt")
        self.assertEqual(len(self.sim.server.effects), 1)

    def test_filter_bypass_is_deduped(self) -> None:
        self.sim.process(self.hello, self.ticket)
        missed = self.sim.process(self.hello, self.ticket, bypass_filter=True)
        self.assertIs(missed.early_status, EarlyDataStatus.DEDUPED)
        self.assertEqual(missed.status, "deduped")
        self.assertIn(ServerState.REPLAYED, missed.states)
        self.assertEqual(missed.effects, 0)
        self.assertEqual(len(self.sim.server.effects), 1)

    def test_no_ticket_takes_one_rtt_path(self) -> None:
        session = self.sim.process(self.hello, None)
        self.assertEqual(session.status, "1-rtt")
        self.assertIn(ServerState.SELECT, session.states)

    def test_legacy_client_gets_no_early_data(self) -> None:
        session = self.sim.process(ClientHello(guard=False), self.ticket)
        self.assertIs(session.early_status, EarlyDataStatus.REJECTED_NO_GUARD)
        self.assertEqual(len(self.sim.server.effects), 0)

    def test_strict_pq_refuses_plaintext_sni(self) -> None:
        cfg = default_hybrid()
        cfg.profile = Profile.STRICT_PQ
        cfg.auth.require_pq_signature = True
        sim = HandshakeSimulator(cfg)
        session = sim.process(ClientHello(ech=False), demo_ticket(sim.now))
        self.assertTrue(session.status.startswith("closed"))


if __name__ == "__main__":
    unittest.main()

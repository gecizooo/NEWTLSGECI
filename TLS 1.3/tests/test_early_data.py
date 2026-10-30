"""Tests for the SUT-CD early-data model.

The important test is ``test_filter_miss_still_no_duplicate_effect``: a replay
that gets past the replay filter is still deduplicated by the commit store.
That is Theorem 2 from the specification, exercised rather than asserted.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from tls13pq.early_data import (
    EarlyDataStatus,
    Server,
    Ticket,
    commit_key,
)

T0 = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)


def make_ticket(nonce: bytes = b"\x01" * 16, epoch: int = 1) -> Ticket:
    return Ticket(nonce=nonce, pq_epoch=epoch, issued_at=T0)


class HappyPathTests(unittest.TestCase):
    def test_accepts_and_commits_once(self) -> None:
        server = Server()
        out = server.handle(make_ticket(), b"token-1", T0 + timedelta(seconds=1))
        self.assertIs(out.status, EarlyDataStatus.ACCEPTED)
        self.assertEqual(out.effects, 1)
        self.assertEqual(server.effects, ["response"])

    def test_speculative_execution_does_not_publish_before_commit(self) -> None:
        server = Server()
        out = server.handle(make_ticket(), b"t", T0 + timedelta(seconds=1),
                            guard=False)
        self.assertIs(out.status, EarlyDataStatus.REJECTED_NO_GUARD)
        self.assertEqual(server.effects, [])


class ReplayTests(unittest.TestCase):
    def test_exact_replay_is_rejected_by_filter(self) -> None:
        server = Server()
        ticket = make_ticket()
        first = server.handle(ticket, b"token-1", T0 + timedelta(seconds=1))
        replay = server.handle(ticket, b"token-1", T0 + timedelta(seconds=2))

        self.assertIs(first.status, EarlyDataStatus.ACCEPTED)
        self.assertIs(replay.status, EarlyDataStatus.REJECTED_REPLAY)
        self.assertEqual(len(server.effects), 1)

    def test_filter_miss_still_no_duplicate_effect(self) -> None:
        server = Server()
        ticket = make_ticket()

        first = server.handle(ticket, b"token-1", T0 + timedelta(seconds=1))
        replay = server.handle(ticket, b"token-1", T0 + timedelta(seconds=2),
                               bypass_filter=True)

        self.assertIs(first.status, EarlyDataStatus.ACCEPTED)
        self.assertIs(replay.status, EarlyDataStatus.DEDUPED)
        self.assertEqual(replay.response, first.response)
        self.assertEqual(len(server.effects), 1, "duplicate side effect!")

    def test_new_token_is_a_new_request(self) -> None:
        server = Server()
        ticket = make_ticket()
        server.handle(ticket, b"token-1", T0 + timedelta(seconds=1))
        second = server.handle(ticket, b"token-2", T0 + timedelta(seconds=1),
                               bypass_filter=True)
        self.assertIs(second.status, EarlyDataStatus.ACCEPTED)
        self.assertEqual(len(server.effects), 2)

    def test_commit_key_depends_on_token_and_nonce(self) -> None:
        a = commit_key(b"n" * 16, b"t1")
        b = commit_key(b"n" * 16, b"t2")
        c = commit_key(b"m" * 16, b"t1")
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(len(a), 32)


class FreshnessTests(unittest.TestCase):
    def test_expired_ticket_is_rejected(self) -> None:
        server = Server()
        ticket = Ticket(nonce=b"\x02" * 16, pq_epoch=1, issued_at=T0,
                        max_early_data=timedelta(seconds=10))
        out = server.handle(ticket, b"t", T0 + timedelta(seconds=11))
        self.assertIs(out.status, EarlyDataStatus.REJECTED_EXPIRED)
        self.assertEqual(server.effects, [])

    def test_old_pq_epoch_is_rejected(self) -> None:
        server = Server(min_pq_epoch=2)
        out = server.handle(make_ticket(epoch=1), b"t", T0 + timedelta(seconds=1))
        self.assertIs(out.status, EarlyDataStatus.REJECTED_EPOCH)

    def test_filter_entries_expire(self) -> None:
        server = Server(window=timedelta(seconds=5))
        ticket = Ticket(nonce=b"\x03" * 16, pq_epoch=1, issued_at=T0,
                        max_early_data=timedelta(seconds=60))
        server.handle(ticket, b"t", T0 + timedelta(seconds=1))
        self.assertEqual(len(server.filter), 1)
        server.filter._expire(T0 + timedelta(seconds=10))
        self.assertEqual(len(server.filter), 0)


class GuardPolicyTests(unittest.TestCase):
    def test_legacy_client_without_guard_is_refused(self) -> None:
        server = Server()
        out = server.handle(make_ticket(), b"t", T0 + timedelta(seconds=1),
                            guard=False)
        self.assertIs(out.status, EarlyDataStatus.REJECTED_NO_GUARD)

    def test_ticket_marked_unguarded_is_refused(self) -> None:
        server = Server()
        ticket = Ticket(nonce=b"\x04" * 16, pq_epoch=1, issued_at=T0,
                        guarded=False)
        out = server.handle(ticket, b"t", T0 + timedelta(seconds=1))
        self.assertIs(out.status, EarlyDataStatus.REJECTED_NO_GUARD)


if __name__ == "__main__":
    unittest.main()

"""Executable model of the SUT-CD early-data state machine (spec Section 5).

Three mechanisms, in order:

1. single-use ticket filter (layer 2),
2. conditional-put commit store (layer 3),
3. application effects that are only published after a successful commit.

``Server.handle()`` runs the full path. ``Server.accept_early_data()`` and
``Server.commit()`` are exposed separately so the handshake simulator can log
the intermediate states without duplicating the security checks.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

__all__ = [
    "EarlyDataStatus",
    "Outcome",
    "Ticket",
    "ReplayFilter",
    "CommitStore",
    "Server",
    "commit_key",
]


class EarlyDataStatus(str, Enum):
    ACCEPTED = "accepted"
    DEDUPED = "deduped"
    REJECTED_NO_GUARD = "rejected_no_guard"
    REJECTED_EPOCH = "rejected_epoch"
    REJECTED_EXPIRED = "rejected_expired"
    REJECTED_REPLAY = "rejected_replay"


@dataclass(frozen=True)
class Ticket:
    nonce: bytes
    pq_epoch: int
    issued_at: datetime
    max_early_data: timedelta = timedelta(seconds=10)
    guarded: bool = True


@dataclass
class Outcome:
    status: EarlyDataStatus
    response: str | None = None
    effects: int = 0


def commit_key(ticket_nonce: bytes, commit_token: bytes,
               client_id: bytes = b"") -> bytes:
    """Domain-separated key for the layer-3 dedup store."""
    h = hashlib.sha256()
    h.update(b"tls13-pq early-data commit v1\x00")
    h.update(client_id)
    h.update(b"\x00")
    h.update(ticket_nonce)
    h.update(commit_token)
    return h.digest()


@dataclass
class ReplayFilter:
    """Exact set with per-entry expiry.

    Fail-closed by construction: there is no code path that returns True when
    the filter is unhealthy, because there is no "unhealthy" state to model.
    A production implementation maps that condition to REJECTED_REPLAY.
    """

    window: timedelta = timedelta(seconds=15)
    _expiry: dict[bytes, datetime] = field(default_factory=dict, repr=False)

    def _expire(self, now: datetime) -> None:
        stale = [nonce for nonce, until in self._expiry.items() if until <= now]
        for nonce in stale:
            del self._expiry[nonce]

    def check_and_set(self, nonce: bytes, now: datetime,
                      expires_at: datetime) -> bool:
        self._expire(now)
        if nonce in self._expiry:
            return False
        self._expiry[nonce] = max(expires_at, now + self.window)
        return True

    def __len__(self) -> int:
        return len(self._expiry)


@dataclass
class CommitStore:
    """Linearizable-by-construction in-process map.

    ``put_if_absent`` returns (created, stored_response). A real deployment
    uses a conditional write in a linearizable store; the contract is the same.
    """

    _records: dict[bytes, str] = field(default_factory=dict, repr=False)

    def put_if_absent(self, key: bytes, response: str) -> tuple[bool, str]:
        existing = self._records.get(key)
        if existing is not None:
            return False, existing
        self._records[key] = response
        return True, response

    def __len__(self) -> int:
        return len(self._records)


@dataclass
class Server:
    min_pq_epoch: int = 1
    window: timedelta = timedelta(seconds=15)
    filter: ReplayFilter = field(default_factory=ReplayFilter)
    commits: CommitStore = field(default_factory=CommitStore)
    effects: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.filter.window = self.window

    # -- layer 2 ---------------------------------------------------------
    def accept_early_data(self, ticket: Ticket, now: datetime,
                          guard: bool = True) -> EarlyDataStatus:
        if not guard or not ticket.guarded:
            return EarlyDataStatus.REJECTED_NO_GUARD
        if ticket.pq_epoch < self.min_pq_epoch:
            return EarlyDataStatus.REJECTED_EPOCH
        if now - ticket.issued_at > ticket.max_early_data:
            return EarlyDataStatus.REJECTED_EXPIRED
        if not self.filter.check_and_set(
            ticket.nonce, now, ticket.issued_at + self.window
        ):
            return EarlyDataStatus.REJECTED_REPLAY
        return EarlyDataStatus.ACCEPTED

    # -- layer 3 ---------------------------------------------------------
    def commit(self, ticket: Ticket, commit_token: bytes,
               produce=lambda: "response") -> Outcome:
        key = commit_key(ticket.nonce, commit_token)
        created, response = self.commits.put_if_absent(key, produce())
        if not created:
            return Outcome(EarlyDataStatus.DEDUPED, response, effects=0)
        self.effects.append(response)
        return Outcome(EarlyDataStatus.ACCEPTED, response, effects=1)

    def handle(self, ticket: Ticket, commit_token: bytes, now: datetime,
               produce=lambda: "response", guard: bool = True,
               bypass_filter: bool = False) -> Outcome:
        """One early-data flight, end to end.

        ``bypass_filter`` exists only for tests and for modelling the
        false-negative case of a probabilistic filter.
        """
        if bypass_filter:
            status = EarlyDataStatus.ACCEPTED
        else:
            status = self.accept_early_data(ticket, now, guard)
        if status is not EarlyDataStatus.ACCEPTED:
            return Outcome(status)
        return self.commit(ticket, commit_token, produce)

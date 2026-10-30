"""Server-side handshake simulator for TLS13-PQ (spec Section 7.4).

This is a *control-plane* simulation: it models the order of states, the
decisions taken, and the sizes on the wire. It does not implement TLS.

The invariant it demonstrates is the one that matters for 0-RTT:

    an effect is published only after a successful conditional put,
    and the conditional put happens only after the replay filter.

Run the demo with ``python3 demo.py`` or ``python3 -m tls13pq demo``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from .config import Config, EarlyDataMode, Group, Profile
from .early_data import EarlyDataStatus, Server, Ticket
from .padding import SizeEstimate, estimate_client_hello

__all__ = [
    "ClientHello",
    "ServerState",
    "Session",
    "HandshakeSimulator",
]


class ServerState(str, Enum):
    LISTEN = "S_LISTEN"
    ECH = "S_ECH"
    ECH_REJECT = "S_ECH_REJECT"
    PSK = "S_PSK"
    TICKET = "S_TICKET"
    REPLAY = "S_REPLAY"
    EARLY = "S_EARLY"
    SELECT = "S_SELECT"
    COMMIT = "S_COMMIT"
    REPLAYED = "S_REPLAYED"
    SEND = "S_SEND"
    OPEN = "S_OPEN"
    CLOSE = "S_CLOSE"


@dataclass(frozen=True)
class ClientHello:
    inner_sni: str = "api.example.com"
    group: Group = Group.X25519_MLKEM768
    ech: bool = True
    early_data: bool = True
    guard: bool = True
    commit_token: bytes = b"\x10" * 16


@dataclass
class Session:
    states: list[ServerState] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    sizes: SizeEstimate | None = None
    status: str = ""
    early_status: EarlyDataStatus | None = None
    effects: int = 0
    response: str | None = None

    def enter(self, state: ServerState) -> None:
        self.states.append(state)

    def log(self, message: str) -> None:
        self.events.append(message)

    @property
    def path(self) -> str:
        return "0-RTT" if self.early_status is EarlyDataStatus.ACCEPTED else "1-RTT"


class HandshakeSimulator:
    def __init__(self, cfg: Config, *, server: Server | None = None,
                 now: datetime | None = None) -> None:
        self.cfg = cfg
        self.now = now or datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
        self.server = server or Server(window=cfg.replay.window)

    # ------------------------------------------------------------------
    def process(self, hello: ClientHello, ticket: Ticket | None = None, *,
                bypass_filter: bool = False) -> Session:
        session = Session()
        session.enter(ServerState.LISTEN)
        session.log(f"profile={self.cfg.profile.value} group={hello.group.label}")

        session.sizes = estimate_client_hello(
            hello.group,
            sni_length=len(hello.inner_sni),
            ech=hello.ech and self.cfg.ech.enabled,
            early_data=hello.early_data,
            classes=self.cfg.padding.classes,
        )
        if session.sizes.segments > 1:
            session.log(
                f"ClientHello {session.sizes.outer_padded} B -> "
                f"{session.sizes.segments} segments (padding class "
                f"{session.sizes.padding_class})"
            )
        else:
            session.log(f"ClientHello {session.sizes.outer_padded} B -> 1 segment")

        # -- ECH --------------------------------------------------------
        if hello.ech and self.cfg.ech.enabled:
            session.enter(ServerState.ECH)
            session.log(f"ECH trial decrypt OK, inner SNI={hello.inner_sni!r}")
        else:
            if self.cfg.profile is Profile.STRICT_PQ:
                session.enter(ServerState.CLOSE)
                session.status = "closed: strict-pq requires ECH"
                session.log("strict-pq: refusing plaintext SNI")
                return session
            session.log("ECH not used: SNI visible on the wire")

        # -- full handshake / no early data ------------------------------
        if ticket is None or not hello.early_data:
            session.enter(ServerState.SELECT)
            session.status = "1-rtt"
            session.log("no usable ticket or no early data -> 1-RTT path")
            return session

        if self.cfg.early_data.mode is EarlyDataMode.OFF:
            session.enter(ServerState.SELECT)
            session.status = "1-rtt"
            session.log("early_data disabled by policy -> 1-RTT path")
            return session

        # -- ticket + replay filter -------------------------------------
        session.enter(ServerState.TICKET)
        session.log(
            f"ticket nonce={ticket.nonce.hex()[:8]}... epoch={ticket.pq_epoch}"
        )

        session.enter(ServerState.REPLAY)
        if bypass_filter:
            status = EarlyDataStatus.ACCEPTED
            session.log("replay filter BYPASSED (test only)")
        else:
            status = self.server.accept_early_data(ticket, self.now,
                                                   guard=hello.guard)
        session.early_status = status

        if status is not EarlyDataStatus.ACCEPTED:
            session.enter(ServerState.SELECT)
            session.status = "1-rtt"
            session.log(f"early_data rejected ({status.value}) -> retransmit at 1-RTT")
            return session

        # -- speculative execution, then commit -------------------------
        session.enter(ServerState.EARLY)
        session.log("speculative execution: request computed, effects buffered")

        outcome = self.server.commit(
            ticket, hello.commit_token,
            produce=lambda: f"response:{ticket.nonce.hex()[:8]}",
        )
        session.early_status = outcome.status
        session.effects = outcome.effects
        session.response = outcome.response

        if outcome.status is EarlyDataStatus.DEDUPED:
            session.enter(ServerState.REPLAYED)
            session.log("conditional put CONFLICT -> stored response replayed")
            session.log(f"application effects so far: {len(self.server.effects)}")
            session.enter(ServerState.SEND)
            session.enter(ServerState.OPEN)
            session.status = "deduped"
            return session

        session.enter(ServerState.COMMIT)
        session.log("conditional put succeeded -> effects may be published")
        session.enter(ServerState.SEND)
        session.enter(ServerState.OPEN)
        session.status = "0-rtt"
        session.log(f"application effects so far: {len(self.server.effects)}")
        return session


def demo_ticket(now: datetime | None = None,
                *, epoch: int = 1,
                lifetime: timedelta = timedelta(seconds=10)) -> Ticket:
    now = now or datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
    return Ticket(
        nonce=b"\xA1" * 16,
        pq_epoch=epoch,
        issued_at=now - timedelta(seconds=1),
        max_early_data=lifetime,
    )

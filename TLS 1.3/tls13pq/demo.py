"""Runnable demonstration of the TLS13-PQ control plane."""

from __future__ import annotations

from datetime import timedelta

from .config import Config, Group, default_hybrid, format_duration, validate
from .early_data import EarlyDataStatus, Ticket
from .handshake import ClientHello, HandshakeSimulator, Session, demo_ticket
from .padding import estimate_client_hello

__all__ = ["run_demo", "main"]


def _print_session(title: str, session: Session) -> None:
    print(f"\n── {title} " + "─" * max(0, 58 - len(title)))
    print(f"   status : {session.status}")
    print(f"   states : {' -> '.join(s.value for s in session.states)}")
    for event in session.events:
        print(f"   · {event}")


def _print_sizes(cfg: Config) -> None:
    print("\n── ClientHello size estimate (ECH on, early data on) " + "─" * 8)
    print(f"   {'group':22} {'CH bytes':>9} {'segments':>9}  padding class")
    for group in (Group.X25519, Group.X25519_MLKEM768, Group.X25519_MLKEM1024):
        est = estimate_client_hello(
            group, sni_length=15, ech=True, early_data=True,
            classes=cfg.padding.classes,
        )
        print(f"   {group.label:22} {est.outer_padded:9} {est.segments:9}"
              f"  {est.padding_class}")


def run_demo(config: Config | None = None) -> int:
    cfg = config or default_hybrid()
    validate(cfg)

    print("TLS13-PQ demo")
    print(f"  profile      : {cfg.profile.value}")
    print(f"  groups       : {', '.join(g.label for g in cfg.groups.offered)}")
    print(f"  early data   : {cfg.early_data.mode.value}, "
          f"max_lifetime={format_duration(cfg.early_data.max_lifetime)}")
    print(f"  replay       : {cfg.replay.ownership.value}/"
          f"{cfg.replay.filter.value}, fail_mode={cfg.replay.fail_mode.value}")
    print(f"  ECH          : {len(cfg.ech.keys)} configs, "
          f"key_ttl={format_duration(cfg.ech.key_ttl)}, "
          f"public_name={cfg.ech.public_name}")

    _print_sizes(cfg)

    sim = HandshakeSimulator(cfg)
    ticket = demo_ticket(sim.now)
    hello = ClientHello()

    first = sim.process(hello, ticket)
    _print_session("1. first 0-RTT flight", first)

    replay = sim.process(hello, ticket)
    _print_session("2. byte-identical replay (filter active)", replay)

    missed = sim.process(hello, ticket, bypass_filter=True)
    _print_session("3. replay with the filter deliberately bypassed", missed)

    expired_ticket = Ticket(
        nonce=b"\xB2" * 16,
        pq_epoch=1,
        issued_at=sim.now - timedelta(seconds=60),
        max_early_data=timedelta(seconds=10),
    )
    expired = sim.process(hello, expired_ticket)
    _print_session("4. expired ticket", expired)

    legacy = sim.process(ClientHello(guard=False), ticket)
    _print_session("5. legacy client (no early_data_guard)", legacy)

    print("\n── result " + "─" * 51)
    print(f"   application effects published: {len(sim.server.effects)}")
    print("   expected: 1. The replay in step 2 is filtered; the replay in")
    print("   step 3 gets past a bypassed filter but is deduplicated by the")
    print("   commit store. Steps 4 and 5 never reach commit.")
    assert len(sim.server.effects) == 1, "duplicate side effect!"
    assert missed.early_status is EarlyDataStatus.DEDUPED
    print("   OK")
    return 0


def main() -> int:
    return run_demo()


if __name__ == "__main__":
    raise SystemExit(main())

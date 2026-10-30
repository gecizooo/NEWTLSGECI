"""TLS13-PQ configuration plane (Python reference port).

Mirrors ``config/protocol_state.go`` field-for-field and invariant-for-invariant.
Standard library only: no pydantic, no attrs.

Design rules carried over from the Go version:

* ``FailMode`` has exactly one value. "Fail open" is not representable.
* Unknown JSON fields are a hard error, so ``"failmode"`` cannot silently
  become a default.
* Groups and signature schemes are written as symbolic names, never decimal
  codepoints.
* ``load_config()`` parses *and* validates; there is no valid-but-unchecked
  intermediate state.

Usage::

    from protocol_state import load_config
    cfg = load_config("config/example.json")

or from the shell::

    python3 config/protocol_state.py config/example.json
"""

from __future__ import annotations

import dataclasses
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any, get_args, get_origin, get_type_hints

__all__ = [
    "ConfigError",
    "Group",
    "SigScheme",
    "Profile",
    "EarlyDataMode",
    "FailMode",
    "OwnershipMode",
    "FilterKind",
    "Config",
    "default_hybrid",
    "format_duration",
    "from_dict",
    "load_config",
    "validate",
    "to_dict",
]


class ConfigError(ValueError):
    """Raised for an unparseable or policy-invalid configuration."""


# ---------------------------------------------------------------------------
# Primitive parsing
# ---------------------------------------------------------------------------

_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)")
_UNIT_SECONDS = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
}


def _parse_duration(value: Any, where: str) -> timedelta:
    """Accept a Go-style duration string ("10s", "1h30m") or seconds."""
    if isinstance(value, timedelta):
        return value
    if isinstance(value, bool):
        raise ConfigError(f"{where}: duration must be a string or number")
    if isinstance(value, (int, float)):
        return timedelta(seconds=float(value))
    if not isinstance(value, str):
        raise ConfigError(f"{where}: duration must be a string or number")

    pos, total = 0, 0.0
    for match in _DURATION_RE.finditer(value):
        if match.start() != pos:
            raise ConfigError(f"{where}: invalid duration {value!r}")
        total += float(match.group(1)) * _UNIT_SECONDS[match.group(2)]
        pos = match.end()
    if pos != len(value) or pos == 0:
        raise ConfigError(f"{where}: invalid duration {value!r}")
    return timedelta(seconds=total)


def format_duration(value: timedelta) -> str:
    """Render like Go: the largest units first, e.g. "1m30s", "24h"."""
    total_ms = round(value.total_seconds() * 1000)
    if total_ms == 0:
        return "0s"
    sign = "-" if total_ms < 0 else ""
    total_ms = abs(total_ms)
    hours, rem = divmod(total_ms, 3_600_000)
    minutes, rem = divmod(rem, 60_000)
    seconds, millis = divmod(rem, 1000)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds:
        parts.append(f"{seconds}s")
    if millis:
        parts.append(f"{millis}ms")
    return sign + "".join(parts)


def _parse_datetime(value: Any, where: str) -> datetime:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise ConfigError(f"{where}: expected an ISO-8601 timestamp")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ConfigError(f"{where}: invalid timestamp {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Codepoints
# ---------------------------------------------------------------------------


class Group(IntEnum):
    X25519 = 0x001D
    SECP256R1 = 0x0017
    X25519_MLKEM768 = 0x11EC
    SECP256R1_MLKEM768 = 0x11EB
    X25519_MLKEM1024 = 0x11ED
    MLKEM768 = 0x0201

    @property
    def is_hybrid(self) -> bool:
        return self in (
            Group.X25519_MLKEM768,
            Group.SECP256R1_MLKEM768,
            Group.X25519_MLKEM1024,
        )

    @property
    def is_post_quantum(self) -> bool:
        return self.is_hybrid or self is Group.MLKEM768

    @property
    def label(self) -> str:
        return _GROUP_LABELS[self]


_GROUP_LABELS = {
    Group.X25519: "X25519",
    Group.SECP256R1: "SecP256r1",
    Group.X25519_MLKEM768: "X25519MLKEM768",
    Group.SECP256R1_MLKEM768: "SecP256r1MLKEM768",
    Group.X25519_MLKEM1024: "X25519MLKEM1024",
    Group.MLKEM768: "MLKEM768",
}


class SigScheme(IntEnum):
    ECDSA_P256 = 0x0403
    ED25519 = 0x0807
    ML_DSA_44 = 0x0904
    ML_DSA_65 = 0x0905
    ML_DSA_87 = 0x0906

    @property
    def is_post_quantum(self) -> bool:
        return self in (SigScheme.ML_DSA_44, SigScheme.ML_DSA_65, SigScheme.ML_DSA_87)

    @property
    def label(self) -> str:
        return _SIG_LABELS[self]


_SIG_LABELS = {
    SigScheme.ECDSA_P256: "ECDSA-P256",
    SigScheme.ED25519: "Ed25519",
    SigScheme.ML_DSA_44: "ML-DSA-44",
    SigScheme.ML_DSA_65: "ML-DSA-65",
    SigScheme.ML_DSA_87: "ML-DSA-87",
}


class Profile(str, Enum):
    COMPAT = "compat"
    HYBRID = "hybrid"
    STRICT_PQ = "strict-pq"


class EarlyDataMode(str, Enum):
    OFF = "off"
    SPECULATIVE = "speculative"
    COMMITTED = "committed"


class FailMode(str, Enum):
    """Exactly one security-relevant value. There is no OPEN."""

    CLOSED = "closed"


class OwnershipMode(str, Enum):
    CONSISTENT_HASH = "consistent_hash"
    REPLICATED = "replicated"


class FilterKind(str, Enum):
    EXACT = "exact"
    FINGERPRINT = "fingerprint"
    EXTERNAL = "external"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class HybridPolicy:
    offered: list[Group] = field(default_factory=list)
    require_pq: bool = False
    allow_pure_pq: bool = False
    key_share_budget_bytes: int = 0
    send_grease_share: bool = False


@dataclass
class AuthPolicy:
    schemes: list[SigScheme] = field(default_factory=list)
    require_pq_signature: bool = False
    allow_composite: bool = False
    min_chain_bits: int = 0


@dataclass
class EarlyDataPolicy:
    mode: EarlyDataMode = EarlyDataMode.OFF
    max_lifetime: timedelta = timedelta(seconds=10)
    max_clock_skew: timedelta = timedelta(seconds=2)
    allow_legacy: bool = False
    idempotent_only: bool = True
    require_commit: bool = True


@dataclass
class ReplayPolicy:
    ownership: OwnershipMode = OwnershipMode.CONSISTENT_HASH
    filter: FilterKind = FilterKind.EXACT
    window: timedelta = timedelta(seconds=15)
    shard_count: int = 0
    bits_per_entry: int = 12
    fail_mode: FailMode = FailMode.CLOSED
    bind_to_address: bool = False
    address_prefix_v4: int = 24
    address_prefix_v6: int = 56


@dataclass
class CommitPolicy:
    store: str = ""
    linearizable: bool = False
    ttl: timedelta = timedelta(seconds=60)
    commit_point: str = "on_send"  # on_send | on_finished
    key_format: str = "hkdf(client_id||ticket_nonce||commit_token)"
    on_conflict: str = "replay_response"


@dataclass
class ECHKey:
    config_id: int = 0
    public_name: str = ""
    kem: str = "X25519HkdfSha256"
    kdf: str = "HkdfSha256"
    aead: str = "Aes128Gcm"
    private_key_handle: str = ""
    not_before: datetime = field(default_factory=lambda: datetime(1970, 1, 1, tzinfo=timezone.utc))
    not_after: datetime = field(default_factory=lambda: datetime(1970, 1, 1, tzinfo=timezone.utc))
    max_name_length: int = 64


@dataclass
class ECHPolicy:
    enabled: bool = False
    keys: list[ECHKey] = field(default_factory=list)
    public_name: str = ""
    min_anonymity_set: int = 64
    key_ttl: timedelta = timedelta(hours=24)
    retry_grace: timedelta = timedelta(hours=2)
    blind_psk_identity: bool = True
    grease_fraction: float = 0.1
    allow_plaintext_fallback: bool = False
    max_retries: int = 1


@dataclass
class PaddingSchedule:
    classes: list[int] = field(default_factory=lambda: [1400, 2816, 4224, 7040])
    pad_certificate: bool = True
    certificate_class: int = 4224


@dataclass
class VerifyPolicy:
    lemmas: list[str] = field(default_factory=list)
    tamarin_path: str = ""
    proverif_path: str = ""
    tla_path: str = ""
    fail_on_proof_failure: bool = False
    model_hash: str = ""


@dataclass
class Config:
    profile: Profile = Profile.COMPAT
    groups: HybridPolicy = field(default_factory=HybridPolicy)
    auth: AuthPolicy = field(default_factory=AuthPolicy)
    early_data: EarlyDataPolicy = field(default_factory=EarlyDataPolicy)
    replay: ReplayPolicy = field(default_factory=ReplayPolicy)
    commit: CommitPolicy = field(default_factory=CommitPolicy)
    ech: ECHPolicy = field(default_factory=ECHPolicy)
    padding: PaddingSchedule = field(default_factory=PaddingSchedule)
    verify: VerifyPolicy = field(default_factory=VerifyPolicy)


# ---------------------------------------------------------------------------
# Strict decoder: mirrors encoding/json's DisallowUnknownFields
# ---------------------------------------------------------------------------

_HINTS: dict[type, dict[str, Any]] = {}


def _hints(cls: type) -> dict[str, Any]:
    if cls not in _HINTS:
        _HINTS[cls] = get_type_hints(cls)
    return _HINTS[cls]


def _enum_from_raw(enum_cls: type[Enum], value: Any, where: str) -> Enum:
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, bool):
        raise ConfigError(f"{where}: expected {enum_cls.__name__}")
    if isinstance(value, int):
        try:
            return enum_cls(value)
        except ValueError as exc:
            raise ConfigError(f"{where}: unknown {enum_cls.__name__} value {value}") from exc
    if isinstance(value, str):
        key = re.sub(r"[^a-z0-9]", "", value.lower())
        for name, member in enum_cls.__members__.items():
            if re.sub(r"[^a-z0-9]", "", name.lower()) == key:
                return member
        if value.lower().startswith("0x"):
            try:
                return enum_cls(int(value, 16))
            except ValueError:
                pass
        raise ConfigError(f"{where}: unknown {enum_cls.__name__} {value!r}")
    raise ConfigError(f"{where}: expected {enum_cls.__name__}")


def _convert(tp: Any, value: Any, where: str) -> Any:
    if tp is timedelta:
        return _parse_duration(value, where)
    if tp is datetime:
        return _parse_datetime(value, where)
    if tp is bool:
        if not isinstance(value, bool):
            raise ConfigError(f"{where}: expected boolean")
        return value
    if tp is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where}: expected integer")
        return value
    if tp is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{where}: expected number")
        return float(value)
    if tp is str:
        if not isinstance(value, str):
            raise ConfigError(f"{where}: expected string")
        return value

    origin = get_origin(tp)
    if origin is list:
        (inner,) = get_args(tp)
        if not isinstance(value, list):
            raise ConfigError(f"{where}: expected array")
        return [_convert(inner, item, f"{where}[{i}]") for i, item in enumerate(value)]

    if isinstance(tp, type) and issubclass(tp, Enum):
        return _enum_from_raw(tp, value, where)

    if isinstance(tp, type) and dataclasses.is_dataclass(tp):
        return _build(tp, value, where)

    raise ConfigError(f"{where}: unsupported field type {tp!r}")


def _build(cls: type, data: Any, where: str) -> Any:
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: expected an object")
    hints = _hints(cls)
    known = {f.name for f in dataclasses.fields(cls)}
    unknown = sorted(set(data) - known)
    if unknown:
        raise ConfigError(f"{where}: unknown field(s): {', '.join(unknown)}")

    kwargs = {}
    for f in dataclasses.fields(cls):
        if f.name in data:
            kwargs[f.name] = _convert(hints[f.name], data[f.name], f"{where}.{f.name}")
    try:
        return cls(**kwargs)
    except TypeError as exc:  # missing required field
        raise ConfigError(f"{where}: {exc}") from exc


# ---------------------------------------------------------------------------
# Validation invariants (the Go Validate() rules, one-for-one)
# ---------------------------------------------------------------------------


def validate(c: Config) -> None:
    errors: list[str] = []

    def add(message: str) -> None:
        errors.append(message)

    if not c.groups.offered:
        add("groups.offered: must not be empty")
    saw_pq = False
    for g in c.groups.offered:
        saw_pq = saw_pq or g.is_post_quantum
        if g is Group.MLKEM768 and not c.groups.allow_pure_pq:
            add(f"groups.offered: {g.label} is PQ-only; set allow_pure_pq")
    if c.groups.require_pq and not saw_pq:
        add("groups.require_pq: no post-quantum group offered")

    if c.profile is Profile.STRICT_PQ:
        if not c.groups.require_pq:
            add("profile strict-pq: groups.require_pq must be true")
        if not c.auth.require_pq_signature:
            add("profile strict-pq: auth.require_pq_signature must be true")
        if c.ech.enabled and c.ech.allow_plaintext_fallback:
            add("profile strict-pq: ech.allow_plaintext_fallback must be false")
        if c.commit.commit_point == "on_finished":
            add("profile strict-pq: commit_point=on_finished re-couples the "
                "response to handshake latency")

    if c.early_data.mode is EarlyDataMode.COMMITTED:
        if not c.commit.linearizable:
            add("early_data.mode=committed requires commit.linearizable=true")
        if not c.commit.store:
            add("early_data.mode=committed requires commit.store")

    if c.commit.key_format != "hkdf(client_id||ticket_nonce||commit_token)":
        add(f"commit.key_format: unsupported {c.commit.key_format!r}")
    if c.commit.on_conflict not in ("replay_response", "reject_425"):
        add(f"commit.on_conflict: unknown {c.commit.on_conflict!r}")
    if c.commit.commit_point not in ("on_send", "on_finished"):
        add(f"commit.commit_point: unknown {c.commit.commit_point!r}")

    if c.replay.fail_mode is not FailMode.CLOSED:
        add("replay.fail_mode: must be 'closed'")
    if c.replay.window < c.early_data.max_lifetime:
        add(f"replay.window ({c.replay.window}) < early_data.max_lifetime "
            f"({c.early_data.max_lifetime})")
    if c.replay.ownership is OwnershipMode.CONSISTENT_HASH and c.replay.shard_count < 1:
        add("replay.shard_count: must be >= 1 for consistent_hash")
    if c.replay.filter is FilterKind.FINGERPRINT and not (8 <= c.replay.bits_per_entry <= 32):
        add("replay.bits_per_entry: must be in [8,32]")
    if c.replay.bind_to_address:
        if not (16 <= c.replay.address_prefix_v4 <= 32):
            add("replay.address_prefix_v4: must be in [16,32]")
        if not (32 <= c.replay.address_prefix_v6 <= 128):
            add("replay.address_prefix_v6: must be in [32,128]")

    if c.ech.enabled:
        if not c.ech.keys and not c.ech.public_name:
            add("ech: enabled but no keys and no public_name")
        if len(c.ech.keys) < 2:
            add(f"ech.keys: publish at least two configs for rotation "
                f"(got {len(c.ech.keys)})")
        if c.ech.key_ttl <= timedelta(0):
            add("ech.key_ttl: must be positive")
        if c.ech.retry_grace <= timedelta(0):
            add("ech.retry_grace: must be positive")
        if c.ech.retry_grace > c.ech.key_ttl:
            add("ech.retry_grace: must not exceed key_ttl; a long grace widens "
                "the retroactive SNI disclosure window")
        if not (0.0 <= c.ech.grease_fraction <= 1.0):
            add("ech.grease_fraction: must be in [0,1]")
        seen: set[int] = set()
        for i, key in enumerate(c.ech.keys):
            if key.config_id in seen:
                add(f"ech.keys[{i}]: duplicate config_id {key.config_id}")
            seen.add(key.config_id)
            if not key.private_key_handle:
                add(f"ech.keys[{i}]: private_key_handle is required")
            if key.not_after < key.not_before:
                add(f"ech.keys[{i}]: not_after precedes not_before")

    if len(c.padding.classes) < 2:
        add("padding.classes: at least two classes are required")
    previous = -1
    for cls in c.padding.classes:
        if cls < 1024:
            add(f"padding.classes: class {cls} is below the 1024-byte floor")
        if cls <= previous:
            add(f"padding.classes: class {cls} is not strictly increasing")
        previous = cls
    if c.padding.pad_certificate and c.padding.certificate_class < 1024:
        add("padding.certificate_class: must be >= 1024")

    if c.profile is not Profile.COMPAT and not c.verify.fail_on_proof_failure:
        add("verify.fail_on_proof_failure: must be true outside compat")

    if errors:
        raise ConfigError("; ".join(errors))


# ---------------------------------------------------------------------------
# Defaults, loading, serialisation
# ---------------------------------------------------------------------------


def default_hybrid() -> Config:
    """The reference 'hybrid' profile: X25519MLKEM768, SUT-CD, ECH, class B/C."""
    return Config(
        profile=Profile.HYBRID,
        groups=HybridPolicy(
            offered=[Group.X25519_MLKEM768, Group.X25519, Group.SECP256R1],
            require_pq=True,
            allow_pure_pq=False,
            key_share_budget_bytes=1400,
            send_grease_share=True,
        ),
        auth=AuthPolicy(
            schemes=[SigScheme.ML_DSA_65, SigScheme.ECDSA_P256, SigScheme.ED25519],
            require_pq_signature=False,  # phase 1: KEX only
            allow_composite=True,
            min_chain_bits=112,
        ),
        early_data=EarlyDataPolicy(
            mode=EarlyDataMode.COMMITTED,
            max_lifetime=timedelta(seconds=10),
            max_clock_skew=timedelta(seconds=2),
            allow_legacy=False,
            idempotent_only=True,
            require_commit=True,
        ),
        replay=ReplayPolicy(
            ownership=OwnershipMode.CONSISTENT_HASH,
            filter=FilterKind.EXACT,
            window=timedelta(seconds=15),
            shard_count=64,
            fail_mode=FailMode.CLOSED,
        ),
        commit=CommitPolicy(
            store="spanner://txn/earlydata",
            linearizable=True,
            ttl=timedelta(seconds=60),
            commit_point="on_send",
        ),
        ech=ECHPolicy(
            enabled=True,
            public_name="cdn.example.net",
            keys=[
                ECHKey(config_id=7, public_name="cdn.example.net",
                       private_key_handle="hsm://ech/placeholder/7"),
                ECHKey(config_id=8, public_name="cdn.example.net",
                       private_key_handle="hsm://ech/placeholder/8"),
            ],
            min_anonymity_set=64,
            key_ttl=timedelta(hours=24),
            retry_grace=timedelta(hours=2),
        ),
        padding=PaddingSchedule(),
        verify=VerifyPolicy(
            lemmas=[f"P{i}" for i in range(1, 11)],
            tamarin_path="formal/tamarin/tls13_pq_replay.spthy",
            proverif_path="formal/proverif/ech_sni.pv",
            tla_path="formal/tla/EarlyData.tla",
            fail_on_proof_failure=True,
        ),
    )


def load_config(path: str | Path) -> Config:
    """Parse + validate. Unknown fields are rejected, as in the Go loader."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return from_dict(data)


def from_dict(data: dict[str, Any]) -> Config:
    """Build + validate from an already-decoded mapping."""
    cfg = _build(Config, data, "config")
    validate(cfg)
    return cfg


def to_dict(value: Any) -> Any:
    """Round-trippable JSON form (labels and duration strings, not integers)."""
    if dataclasses.is_dataclass(value):
        return {f.name: to_dict(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, (Group, SigScheme)):
        return value.label
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, timedelta):
        return format_duration(value)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, list):
        return [to_dict(item) for item in value]
    return value


def _main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else "config/example.json"
    try:
        cfg = load_config(path)
    except (OSError, json.JSONDecodeError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(to_dict(cfg), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))

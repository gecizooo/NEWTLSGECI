#!/usr/bin/env python3
"""TLS 1.3 + TLS 1.4 + TLS 1.5 -- mindhárom verzió egyetlen Python szkriptben.

A /home/mart/TLS alatti három különálló projekt egy fájlba portolt változata:

  * TLS 1.3  -- TLS13-PQ: szigorú konfigurációs modell, 0-RTT replay/dedup
                szimulátor, ECH padding számítás. Csak standard library.
  * TLS 1.4  -- hibrid X25519 + RSA-OAEP kézfogás, X.509 ellenőrzés,
                AES-GCM rekordréteg, KeyUpdate, klienshitelesítés.
                A C++/OpenSSL implementáció Python portja (cryptography).
  * TLS 1.5  -- TowerStack/1.5: X25519 + ML-KEM-768, ML-DSA-65,
                háromrétegű AEAD/CTR+HMAC stack, replay ablak, rekey.

Futtatás:

    python3 tls_versions.py                 # mindhárom demó
    python3 tls_versions.py 1.3 demo
    python3 tls_versions.py 1.3 validate example.json
    python3 tls_versions.py 1.4 demo
    python3 tls_versions.py 1.4 selftest
    python3 tls_versions.py 1.4 gen-certs ./certs
    python3 tls_versions.py 1.4 server --port 4433 --cert-dir ./certs
    python3 tls_versions.py 1.4 client --host 127.0.0.1 --port 4433
    python3 tls_versions.py 1.5 demo
    python3 tls_versions.py selftest

FIGYELEM: a TLS 1.4 és TLS 1.5 itt oktatási célú, saját protokolltervezet.
Nem IETF-szabványok, nem wire-kompatibilisek a valódi TLS-sel, és nem
produkciós kriptográfiai kódok.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import struct
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any, Protocol, get_args, get_origin, get_type_hints

try:  # A TLS 1.3 rész cryptography nélkül is működik.
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import (
        ec,
        ed25519,
        mldsa,
        mlkem,
        padding as asym_padding,
        rsa,
        x25519,
    )
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - csak a környezet hiányosságát jelzi
    _HAVE_CRYPTO = False


def _require_crypto() -> None:
    if not _HAVE_CRYPTO:
        raise RuntimeError(
            "ehhez a részhez kell a 'cryptography' csomag: "
            "python3 -m pip install cryptography"
        )


# ===========================================================================
# TLS 1.3 -- TLS13-PQ
# ===========================================================================
#
# Tiszta Python referencia-modell. Nem valódi TLS: a konfigurációs síkot, a
# 0-RTT replay/dedup állapotgépet és az ECH padding aritmetikát modellezi.
# ===========================================================================


class T13ConfigError(ValueError):
    """Érvénytelen vagy feldolgozhatatlan konfiguráció."""


# ---------------------------------------------------------------------------
# T13: primitív parsolás
# ---------------------------------------------------------------------------

_T13_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)")
_T13_UNIT_SECONDS = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
}


def t13_parse_duration(value: Any, where: str) -> timedelta:
    if isinstance(value, timedelta):
        return value
    if isinstance(value, bool):
        raise T13ConfigError(f"{where}: duration must be a string or number")
    if isinstance(value, (int, float)):
        return timedelta(seconds=float(value))
    if not isinstance(value, str):
        raise T13ConfigError(f"{where}: duration must be a string or number")

    pos, total = 0, 0.0
    for match in _T13_DURATION_RE.finditer(value):
        if match.start() != pos:
            raise T13ConfigError(f"{where}: invalid duration {value!r}")
        total += float(match.group(1)) * _T13_UNIT_SECONDS[match.group(2)]
        pos = match.end()
    if pos != len(value) or pos == 0:
        raise T13ConfigError(f"{where}: invalid duration {value!r}")
    return timedelta(seconds=total)


def t13_format_duration(value: timedelta) -> str:
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


def t13_parse_datetime(value: Any, where: str) -> datetime:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise T13ConfigError(f"{where}: expected an ISO-8601 timestamp")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise T13ConfigError(f"{where}: invalid timestamp {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# T13: kódpontok
# ---------------------------------------------------------------------------


class T13Group(IntEnum):
    X25519 = 0x001D
    SECP256R1 = 0x0017
    X25519_MLKEM768 = 0x11EC
    SECP256R1_MLKEM768 = 0x11EB
    X25519_MLKEM1024 = 0x11ED
    MLKEM768 = 0x0201

    @property
    def is_hybrid(self) -> bool:
        return self in (
            T13Group.X25519_MLKEM768,
            T13Group.SECP256R1_MLKEM768,
            T13Group.X25519_MLKEM1024,
        )

    @property
    def is_post_quantum(self) -> bool:
        return self.is_hybrid or self is T13Group.MLKEM768

    @property
    def label(self) -> str:
        return _T13_GROUP_LABELS[self]


_T13_GROUP_LABELS = {
    T13Group.X25519: "X25519",
    T13Group.SECP256R1: "SecP256r1",
    T13Group.X25519_MLKEM768: "X25519MLKEM768",
    T13Group.SECP256R1_MLKEM768: "SecP256r1MLKEM768",
    T13Group.X25519_MLKEM1024: "X25519MLKEM1024",
    T13Group.MLKEM768: "MLKEM768",
}


class T13SigScheme(IntEnum):
    ECDSA_P256 = 0x0403
    ED25519 = 0x0807
    ML_DSA_44 = 0x0904
    ML_DSA_65 = 0x0905
    ML_DSA_87 = 0x0906

    @property
    def is_post_quantum(self) -> bool:
        return self in (T13SigScheme.ML_DSA_44, T13SigScheme.ML_DSA_65,
                        T13SigScheme.ML_DSA_87)

    @property
    def label(self) -> str:
        return _T13_SIG_LABELS[self]


_T13_SIG_LABELS = {
    T13SigScheme.ECDSA_P256: "ECDSA-P256",
    T13SigScheme.ED25519: "Ed25519",
    T13SigScheme.ML_DSA_44: "ML-DSA-44",
    T13SigScheme.ML_DSA_65: "ML-DSA-65",
    T13SigScheme.ML_DSA_87: "ML-DSA-87",
}


class T13Profile(str, Enum):
    COMPAT = "compat"
    HYBRID = "hybrid"
    STRICT_PQ = "strict-pq"


class T13EarlyDataMode(str, Enum):
    OFF = "off"
    SPECULATIVE = "speculative"
    COMMITTED = "committed"


class T13FailMode(str, Enum):
    """Pontosan egy biztonsági érték. Nincs OPEN."""

    CLOSED = "closed"


class T13OwnershipMode(str, Enum):
    CONSISTENT_HASH = "consistent_hash"
    REPLICATED = "replicated"


class T13FilterKind(str, Enum):
    EXACT = "exact"
    FINGERPRINT = "fingerprint"
    EXTERNAL = "external"


# ---------------------------------------------------------------------------
# T13: adatmodell
# ---------------------------------------------------------------------------


@dataclass
class T13HybridPolicy:
    offered: list[T13Group] = field(default_factory=list)
    require_pq: bool = False
    allow_pure_pq: bool = False
    key_share_budget_bytes: int = 0
    send_grease_share: bool = False


@dataclass
class T13AuthPolicy:
    schemes: list[T13SigScheme] = field(default_factory=list)
    require_pq_signature: bool = False
    allow_composite: bool = False
    min_chain_bits: int = 0


@dataclass
class T13EarlyDataPolicy:
    mode: T13EarlyDataMode = T13EarlyDataMode.OFF
    max_lifetime: timedelta = timedelta(seconds=10)
    max_clock_skew: timedelta = timedelta(seconds=2)
    allow_legacy: bool = False
    idempotent_only: bool = True
    require_commit: bool = True


@dataclass
class T13ReplayPolicy:
    ownership: T13OwnershipMode = T13OwnershipMode.CONSISTENT_HASH
    filter: T13FilterKind = T13FilterKind.EXACT
    window: timedelta = timedelta(seconds=15)
    shard_count: int = 0
    bits_per_entry: int = 12
    fail_mode: T13FailMode = T13FailMode.CLOSED
    bind_to_address: bool = False
    address_prefix_v4: int = 24
    address_prefix_v6: int = 56


@dataclass
class T13CommitPolicy:
    store: str = ""
    linearizable: bool = False
    ttl: timedelta = timedelta(seconds=60)
    commit_point: str = "on_send"
    key_format: str = "hkdf(client_id||ticket_nonce||commit_token)"
    on_conflict: str = "replay_response"


@dataclass
class T13ECHKey:
    config_id: int = 0
    public_name: str = ""
    kem: str = "X25519HkdfSha256"
    kdf: str = "HkdfSha256"
    aead: str = "Aes128Gcm"
    private_key_handle: str = ""
    not_before: datetime = field(
        default_factory=lambda: datetime(1970, 1, 1, tzinfo=timezone.utc)
    )
    not_after: datetime = field(
        default_factory=lambda: datetime(1970, 1, 1, tzinfo=timezone.utc)
    )
    max_name_length: int = 64


@dataclass
class T13ECHPolicy:
    enabled: bool = False
    keys: list[T13ECHKey] = field(default_factory=list)
    public_name: str = ""
    min_anonymity_set: int = 64
    key_ttl: timedelta = timedelta(hours=24)
    retry_grace: timedelta = timedelta(hours=2)
    blind_psk_identity: bool = True
    grease_fraction: float = 0.1
    allow_plaintext_fallback: bool = False
    max_retries: int = 1


@dataclass
class T13PaddingSchedule:
    classes: list[int] = field(default_factory=lambda: [1400, 2816, 4224, 7040])
    pad_certificate: bool = True
    certificate_class: int = 4224


@dataclass
class T13VerifyPolicy:
    lemmas: list[str] = field(default_factory=list)
    tamarin_path: str = ""
    proverif_path: str = ""
    tla_path: str = ""
    fail_on_proof_failure: bool = False
    model_hash: str = ""


@dataclass
class T13Config:
    profile: T13Profile = T13Profile.COMPAT
    groups: T13HybridPolicy = field(default_factory=T13HybridPolicy)
    auth: T13AuthPolicy = field(default_factory=T13AuthPolicy)
    early_data: T13EarlyDataPolicy = field(default_factory=T13EarlyDataPolicy)
    replay: T13ReplayPolicy = field(default_factory=T13ReplayPolicy)
    commit: T13CommitPolicy = field(default_factory=T13CommitPolicy)
    ech: T13ECHPolicy = field(default_factory=T13ECHPolicy)
    padding: T13PaddingSchedule = field(default_factory=T13PaddingSchedule)
    verify: T13VerifyPolicy = field(default_factory=T13VerifyPolicy)


# ---------------------------------------------------------------------------
# T13: szigorú JSON dekóder (ismeretlen mező = hiba)
# ---------------------------------------------------------------------------

_T13_HINTS: dict[type, dict[str, Any]] = {}


def _t13_hints(cls: type) -> dict[str, Any]:
    if cls not in _T13_HINTS:
        _T13_HINTS[cls] = get_type_hints(cls)
    return _T13_HINTS[cls]


def _t13_enum_from_raw(enum_cls: type[Enum], value: Any, where: str) -> Enum:
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, bool):
        raise T13ConfigError(f"{where}: expected {enum_cls.__name__}")
    if isinstance(value, int):
        try:
            return enum_cls(value)
        except ValueError as exc:
            raise T13ConfigError(
                f"{where}: unknown {enum_cls.__name__} value {value}"
            ) from exc
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
        raise T13ConfigError(f"{where}: unknown {enum_cls.__name__} {value!r}")
    raise T13ConfigError(f"{where}: expected {enum_cls.__name__}")


def _t13_convert(tp: Any, value: Any, where: str) -> Any:
    if tp is timedelta:
        return t13_parse_duration(value, where)
    if tp is datetime:
        return t13_parse_datetime(value, where)
    if tp is bool:
        if not isinstance(value, bool):
            raise T13ConfigError(f"{where}: expected boolean")
        return value
    if tp is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise T13ConfigError(f"{where}: expected integer")
        return value
    if tp is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise T13ConfigError(f"{where}: expected number")
        return float(value)
    if tp is str:
        if not isinstance(value, str):
            raise T13ConfigError(f"{where}: expected string")
        return value

    origin = get_origin(tp)
    if origin is list:
        (inner,) = get_args(tp)
        if not isinstance(value, list):
            raise T13ConfigError(f"{where}: expected array")
        return [
            _t13_convert(inner, item, f"{where}[{i}]")
            for i, item in enumerate(value)
        ]

    if isinstance(tp, type) and issubclass(tp, Enum):
        return _t13_enum_from_raw(tp, value, where)

    if isinstance(tp, type) and dataclasses.is_dataclass(tp):
        return _t13_build(tp, value, where)

    raise T13ConfigError(f"{where}: unsupported field type {tp!r}")


def _t13_build(cls: type, data: Any, where: str) -> Any:
    if not isinstance(data, dict):
        raise T13ConfigError(f"{where}: expected an object")
    hints = _t13_hints(cls)
    known = {f.name for f in dataclasses.fields(cls)}
    unknown = sorted(set(data) - known)
    if unknown:
        raise T13ConfigError(f"{where}: unknown field(s): {', '.join(unknown)}")

    kwargs = {}
    for f in dataclasses.fields(cls):
        if f.name in data:
            kwargs[f.name] = _t13_convert(
                hints[f.name], data[f.name], f"{where}.{f.name}"
            )
    try:
        return cls(**kwargs)
    except TypeError as exc:
        raise T13ConfigError(f"{where}: {exc}") from exc


# ---------------------------------------------------------------------------
# T13: validációs invariánsok
# ---------------------------------------------------------------------------


def t13_validate(c: T13Config) -> None:
    errors: list[str] = []

    def add(message: str) -> None:
        errors.append(message)

    if not c.groups.offered:
        add("groups.offered: must not be empty")
    saw_pq = False
    for g in c.groups.offered:
        saw_pq = saw_pq or g.is_post_quantum
        if g is T13Group.MLKEM768 and not c.groups.allow_pure_pq:
            add(f"groups.offered: {g.label} is PQ-only; set allow_pure_pq")
    if c.groups.require_pq and not saw_pq:
        add("groups.require_pq: no post-quantum group offered")

    if c.profile is T13Profile.STRICT_PQ:
        if not c.groups.require_pq:
            add("profile strict-pq: groups.require_pq must be true")
        if not c.auth.require_pq_signature:
            add("profile strict-pq: auth.require_pq_signature must be true")
        if c.ech.enabled and c.ech.allow_plaintext_fallback:
            add("profile strict-pq: ech.allow_plaintext_fallback must be false")
        if c.commit.commit_point == "on_finished":
            add("profile strict-pq: commit_point=on_finished re-couples the "
                "response to handshake latency")

    if c.early_data.mode is T13EarlyDataMode.COMMITTED:
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

    if c.replay.fail_mode is not T13FailMode.CLOSED:
        add("replay.fail_mode: must be 'closed'")
    if c.replay.window < c.early_data.max_lifetime:
        add(f"replay.window ({c.replay.window}) < early_data.max_lifetime "
            f"({c.early_data.max_lifetime})")
    if (c.replay.ownership is T13OwnershipMode.CONSISTENT_HASH
            and c.replay.shard_count < 1):
        add("replay.shard_count: must be >= 1 for consistent_hash")
    if (c.replay.filter is T13FilterKind.FINGERPRINT
            and not (8 <= c.replay.bits_per_entry <= 32)):
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

    if c.profile is not T13Profile.COMPAT and not c.verify.fail_on_proof_failure:
        add("verify.fail_on_proof_failure: must be true outside compat")

    if errors:
        raise T13ConfigError("; ".join(errors))


def t13_default_hybrid() -> T13Config:
    """A referencia 'hybrid' profil: X25519MLKEM768, SUT-CD, ECH, B/C padding."""
    return T13Config(
        profile=T13Profile.HYBRID,
        groups=T13HybridPolicy(
            offered=[T13Group.X25519_MLKEM768, T13Group.X25519, T13Group.SECP256R1],
            require_pq=True,
            allow_pure_pq=False,
            key_share_budget_bytes=1400,
            send_grease_share=True,
        ),
        auth=T13AuthPolicy(
            schemes=[T13SigScheme.ML_DSA_65, T13SigScheme.ECDSA_P256,
                     T13SigScheme.ED25519],
            require_pq_signature=False,
            allow_composite=True,
            min_chain_bits=112,
        ),
        early_data=T13EarlyDataPolicy(
            mode=T13EarlyDataMode.COMMITTED,
            max_lifetime=timedelta(seconds=10),
            max_clock_skew=timedelta(seconds=2),
            allow_legacy=False,
            idempotent_only=True,
            require_commit=True,
        ),
        replay=T13ReplayPolicy(
            ownership=T13OwnershipMode.CONSISTENT_HASH,
            filter=T13FilterKind.EXACT,
            window=timedelta(seconds=15),
            shard_count=64,
            fail_mode=T13FailMode.CLOSED,
        ),
        commit=T13CommitPolicy(
            store="spanner://txn/earlydata",
            linearizable=True,
            ttl=timedelta(seconds=60),
            commit_point="on_send",
        ),
        ech=T13ECHPolicy(
            enabled=True,
            public_name="cdn.example.net",
            keys=[
                T13ECHKey(config_id=7, public_name="cdn.example.net",
                          private_key_handle="hsm://ech/placeholder/7"),
                T13ECHKey(config_id=8, public_name="cdn.example.net",
                          private_key_handle="hsm://ech/placeholder/8"),
            ],
            min_anonymity_set=64,
            key_ttl=timedelta(hours=24),
            retry_grace=timedelta(hours=2),
        ),
        padding=T13PaddingSchedule(),
        verify=T13VerifyPolicy(
            lemmas=[f"P{i}" for i in range(1, 11)],
            tamarin_path="formal/tamarin/tls13_pq_replay.spthy",
            proverif_path="formal/proverif/ech_sni.pv",
            tla_path="formal/tla/EarlyData.tla",
            fail_on_proof_failure=True,
        ),
    )


def t13_from_dict(data: dict[str, Any]) -> T13Config:
    cfg = _t13_build(T13Config, data, "config")
    t13_validate(cfg)
    return cfg


def t13_load_config(path: str | Path) -> T13Config:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise T13ConfigError("config: expected an object")
    return t13_from_dict(data)


def t13_to_dict(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {f.name: t13_to_dict(getattr(value, f.name))
                for f in dataclasses.fields(value)}
    if isinstance(value, (T13Group, T13SigScheme)):
        return value.label
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, timedelta):
        return t13_format_duration(value)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, list):
        return [t13_to_dict(item) for item in value]
    return value


# A TLS 1.3 példakonfiguráció beépítve, hogy a szkript önmagában is működjön.
T13_EXAMPLE_CONFIG: dict[str, Any] = {
    "profile": "hybrid",
    "groups": {
        "offered": ["X25519MLKEM768", "X25519", "SecP256r1"],
        "require_pq": True,
        "allow_pure_pq": False,
        "key_share_budget_bytes": 1400,
        "send_grease_share": True,
    },
    "auth": {
        "schemes": ["ML-DSA-65", "ECDSA-P256", "Ed25519"],
        "require_pq_signature": False,
        "allow_composite": True,
        "min_chain_bits": 112,
    },
    "early_data": {
        "mode": "committed",
        "max_lifetime": "10s",
        "max_clock_skew": "2s",
        "allow_legacy": False,
        "idempotent_only": True,
        "require_commit": True,
    },
    "replay": {
        "ownership": "consistent_hash",
        "filter": "exact",
        "window": "15s",
        "shard_count": 64,
        "bits_per_entry": 12,
        "fail_mode": "closed",
        "bind_to_address": False,
        "address_prefix_v4": 24,
        "address_prefix_v6": 56,
    },
    "commit": {
        "store": "spanner://txn/earlydata",
        "linearizable": True,
        "ttl": "60s",
        "commit_point": "on_send",
        "key_format": "hkdf(client_id||ticket_nonce||commit_token)",
        "on_conflict": "replay_response",
    },
    "ech": {
        "enabled": True,
        "public_name": "cdn.example.net",
        "min_anonymity_set": 64,
        "key_ttl": "24h",
        "retry_grace": "2h",
        "blind_psk_identity": True,
        "grease_fraction": 0.1,
        "allow_plaintext_fallback": False,
        "max_retries": 1,
        "keys": [
            {
                "config_id": 7,
                "public_name": "cdn.example.net",
                "kem": "X25519HkdfSha256",
                "kdf": "HkdfSha256",
                "aead": "Aes128Gcm",
                "private_key_handle": "hsm://ech/2026-10-29/7",
                "not_before": "2026-10-29T00:00:00Z",
                "not_after": "2026-10-30T00:00:00Z",
                "max_name_length": 64,
            },
            {
                "config_id": 8,
                "public_name": "cdn.example.net",
                "kem": "X25519HkdfSha256",
                "kdf": "HkdfSha256",
                "aead": "Aes128Gcm",
                "private_key_handle": "hsm://ech/2026-10-29/8",
                "not_before": "2026-10-29T12:00:00Z",
                "not_after": "2026-10-30T12:00:00Z",
                "max_name_length": 64,
            },
        ],
    },
    "padding": {
        "classes": [1400, 2816, 4224, 7040],
        "pad_certificate": True,
        "certificate_class": 4224,
    },
    "verify": {
        "lemmas": [f"P{i}" for i in range(1, 11)],
        "tamarin_path": "formal/tamarin/tls13_pq_replay.spthy",
        "proverif_path": "formal/proverif/ech_sni.pv",
        "tla_path": "formal/tla/EarlyData.tla",
        "fail_on_proof_failure": True,
        "model_hash": "sha256:" + "0" * 64,
    },
}


# ---------------------------------------------------------------------------
# T13: early-data állapotgép (SUT-CD)
# ---------------------------------------------------------------------------


class T13EarlyDataStatus(str, Enum):
    ACCEPTED = "accepted"
    DEDUPED = "deduped"
    REJECTED_NO_GUARD = "rejected_no_guard"
    REJECTED_EPOCH = "rejected_epoch"
    REJECTED_EXPIRED = "rejected_expired"
    REJECTED_REPLAY = "rejected_replay"


@dataclass(frozen=True)
class T13Ticket:
    nonce: bytes
    pq_epoch: int
    issued_at: datetime
    max_early_data: timedelta = timedelta(seconds=10)
    guarded: bool = True


@dataclass
class T13Outcome:
    status: T13EarlyDataStatus
    response: str | None = None
    effects: int = 0


def t13_commit_key(ticket_nonce: bytes, commit_token: bytes,
                   client_id: bytes = b"") -> bytes:
    h = hashlib.sha256()
    h.update(b"tls13-pq early-data commit v1\x00")
    h.update(client_id)
    h.update(b"\x00")
    h.update(ticket_nonce)
    h.update(commit_token)
    return h.digest()


@dataclass
class T13ReplayFilter:
    """Pontos halmaz lejárattal; fail-closed konstrukció."""

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
class T13CommitStore:
    """Lineáris konzisztenciájú, folyamatban lévő feltételes írás."""

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
class T13Server:
    min_pq_epoch: int = 1
    window: timedelta = timedelta(seconds=15)
    filter: T13ReplayFilter = field(default_factory=T13ReplayFilter)
    commits: T13CommitStore = field(default_factory=T13CommitStore)
    effects: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.filter.window = self.window

    def accept_early_data(self, ticket: T13Ticket, now: datetime,
                          guard: bool = True) -> T13EarlyDataStatus:
        if not guard or not ticket.guarded:
            return T13EarlyDataStatus.REJECTED_NO_GUARD
        if ticket.pq_epoch < self.min_pq_epoch:
            return T13EarlyDataStatus.REJECTED_EPOCH
        if now - ticket.issued_at > ticket.max_early_data:
            return T13EarlyDataStatus.REJECTED_EXPIRED
        if not self.filter.check_and_set(
            ticket.nonce, now, ticket.issued_at + self.window
        ):
            return T13EarlyDataStatus.REJECTED_REPLAY
        return T13EarlyDataStatus.ACCEPTED

    def commit(self, ticket: T13Ticket, commit_token: bytes,
               produce=lambda: "response") -> T13Outcome:
        key = t13_commit_key(ticket.nonce, commit_token)
        created, response = self.commits.put_if_absent(key, produce())
        if not created:
            return T13Outcome(T13EarlyDataStatus.DEDUPED, response, effects=0)
        self.effects.append(response)
        return T13Outcome(T13EarlyDataStatus.ACCEPTED, response, effects=1)

    def handle(self, ticket: T13Ticket, commit_token: bytes, now: datetime,
               produce=lambda: "response", guard: bool = True,
               bypass_filter: bool = False) -> T13Outcome:
        if bypass_filter:
            status = T13EarlyDataStatus.ACCEPTED
        else:
            status = self.accept_early_data(ticket, now, guard)
        if status is not T13EarlyDataStatus.ACCEPTED:
            return T13Outcome(status)
        return self.commit(ticket, commit_token, produce)


# ---------------------------------------------------------------------------
# T13: ECH padding és méretaritmetika
# ---------------------------------------------------------------------------

T13_GROUP_SHARE_BYTES: dict[T13Group, int] = {
    T13Group.X25519: 32,
    T13Group.SECP256R1: 65,
    T13Group.X25519_MLKEM768: 1216,
    T13Group.SECP256R1_MLKEM768: 1249,
    T13Group.X25519_MLKEM1024: 1600,
    T13Group.MLKEM768: 1184,
}

_T13_BASE_INNER = 220
_T13_BASE_OUTER = 160
_T13_GUARD_BYTES = 18
_T13_HPKE_OVERHEAD = 48
_T13_ECH_EXT = 20
_T13_IP_TCP_HEADERS = 40


def t13_pad_to_class(length: int, classes: list[int]) -> int:
    if length <= 0:
        raise ValueError("length must be positive")
    if not classes:
        raise ValueError("classes must not be empty")
    for cls in classes:
        if length <= cls:
            return cls
    last = classes[-1]
    return ((length + last - 1) // last) * last


def t13_segments(length: int, mss: int = 1460) -> int:
    if length <= 0:
        return 0
    return (length + _T13_IP_TCP_HEADERS + mss - 1) // mss


@dataclass(frozen=True)
class T13SizeEstimate:
    inner: int
    inner_padded: int
    outer: int
    outer_padded: int
    segments: int
    padding_class: int

    def as_dict(self) -> dict[str, int]:
        return {
            "inner": self.inner,
            "inner_padded": self.inner_padded,
            "outer": self.outer,
            "outer_padded": self.outer_padded,
            "segments": self.segments,
            "padding_class": self.padding_class,
        }


def t13_estimate_client_hello(group: T13Group, sni_length: int, *,
                              ech: bool, early_data: bool,
                              classes: list[int],
                              mss: int = 1460) -> T13SizeEstimate:
    if group not in T13_GROUP_SHARE_BYTES:
        raise ValueError(f"unknown group {group!r}")

    inner = _T13_BASE_INNER + T13_GROUP_SHARE_BYTES[group] + sni_length
    if early_data:
        inner += _T13_GUARD_BYTES

    overhead = _T13_BASE_OUTER + _T13_HPKE_OVERHEAD + _T13_ECH_EXT

    if ech:
        outer = _T13_BASE_OUTER + inner + _T13_HPKE_OVERHEAD + _T13_ECH_EXT
        outer_padded = t13_pad_to_class(outer, classes)
        inner_padded = outer_padded - overhead
        assert inner_padded >= inner
    else:
        inner_padded = t13_pad_to_class(inner, classes)
        outer = inner
        outer_padded = inner_padded

    return T13SizeEstimate(
        inner=inner,
        inner_padded=inner_padded,
        outer=outer,
        outer_padded=outer_padded,
        segments=t13_segments(outer_padded, mss),
        padding_class=outer_padded,
    )


# ---------------------------------------------------------------------------
# T13: szerver oldali kézfogás-szimulátor
# ---------------------------------------------------------------------------


class T13ServerState(str, Enum):
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
class T13ClientHello:
    inner_sni: str = "api.example.com"
    group: T13Group = T13Group.X25519_MLKEM768
    ech: bool = True
    early_data: bool = True
    guard: bool = True
    commit_token: bytes = b"\x10" * 16


@dataclass
class T13Session:
    states: list[T13ServerState] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    sizes: T13SizeEstimate | None = None
    status: str = ""
    early_status: T13EarlyDataStatus | None = None
    effects: int = 0
    response: str | None = None

    def enter(self, state: T13ServerState) -> None:
        self.states.append(state)

    def log(self, message: str) -> None:
        self.events.append(message)

    @property
    def path(self) -> str:
        if self.early_status is T13EarlyDataStatus.ACCEPTED:
            return "0-RTT"
        return "1-RTT"


class T13HandshakeSimulator:
    def __init__(self, cfg: T13Config, *, server: T13Server | None = None,
                 now: datetime | None = None) -> None:
        self.cfg = cfg
        self.now = now or datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
        self.server = server or T13Server(window=cfg.replay.window)

    def process(self, hello: T13ClientHello, ticket: T13Ticket | None = None,
                *, bypass_filter: bool = False) -> T13Session:
        session = T13Session()
        session.enter(T13ServerState.LISTEN)
        session.log(f"profile={self.cfg.profile.value} group={hello.group.label}")

        session.sizes = t13_estimate_client_hello(
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

        if hello.ech and self.cfg.ech.enabled:
            session.enter(T13ServerState.ECH)
            session.log(f"ECH trial decrypt OK, inner SNI={hello.inner_sni!r}")
        else:
            if self.cfg.profile is T13Profile.STRICT_PQ:
                session.enter(T13ServerState.CLOSE)
                session.status = "closed: strict-pq requires ECH"
                session.log("strict-pq: refusing plaintext SNI")
                return session
            session.log("ECH not used: SNI visible on the wire")

        if ticket is None or not hello.early_data:
            session.enter(T13ServerState.SELECT)
            session.status = "1-rtt"
            session.log("no usable ticket or no early data -> 1-RTT path")
            return session

        if self.cfg.early_data.mode is T13EarlyDataMode.OFF:
            session.enter(T13ServerState.SELECT)
            session.status = "1-rtt"
            session.log("early_data disabled by policy -> 1-RTT path")
            return session

        session.enter(T13ServerState.TICKET)
        session.log(
            f"ticket nonce={ticket.nonce.hex()[:8]}... epoch={ticket.pq_epoch}"
        )

        session.enter(T13ServerState.REPLAY)
        if bypass_filter:
            status = T13EarlyDataStatus.ACCEPTED
            session.log("replay filter BYPASSED (test only)")
        else:
            status = self.server.accept_early_data(ticket, self.now,
                                                   guard=hello.guard)
        session.early_status = status

        if status is not T13EarlyDataStatus.ACCEPTED:
            session.enter(T13ServerState.SELECT)
            session.status = "1-rtt"
            session.log(f"early_data rejected ({status.value}) -> retransmit at 1-RTT")
            return session

        session.enter(T13ServerState.EARLY)
        session.log("speculative execution: request computed, effects buffered")

        outcome = self.server.commit(
            ticket, hello.commit_token,
            produce=lambda: f"response:{ticket.nonce.hex()[:8]}",
        )
        session.early_status = outcome.status
        session.effects = outcome.effects
        session.response = outcome.response

        if outcome.status is T13EarlyDataStatus.DEDUPED:
            session.enter(T13ServerState.REPLAYED)
            session.log("conditional put CONFLICT -> stored response replayed")
            session.log(f"application effects so far: {len(self.server.effects)}")
            session.enter(T13ServerState.SEND)
            session.enter(T13ServerState.OPEN)
            session.status = "deduped"
            return session

        session.enter(T13ServerState.COMMIT)
        session.log("conditional put succeeded -> effects may be published")
        session.enter(T13ServerState.SEND)
        session.enter(T13ServerState.OPEN)
        session.status = "0-rtt"
        session.log(f"application effects so far: {len(self.server.effects)}")
        return session


def t13_demo_ticket(now: datetime | None = None, *, epoch: int = 1,
                    lifetime: timedelta = timedelta(seconds=10)) -> T13Ticket:
    now = now or datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
    return T13Ticket(
        nonce=b"\xA1" * 16,
        pq_epoch=epoch,
        issued_at=now - timedelta(seconds=1),
        max_early_data=lifetime,
    )


# ---------------------------------------------------------------------------
# T13: demó
# ---------------------------------------------------------------------------


def _t13_print_session(title: str, session: T13Session) -> None:
    print(f"\n── {title} " + "─" * max(0, 58 - len(title)))
    print(f"   status : {session.status}")
    print(f"   states : {' -> '.join(s.value for s in session.states)}")
    for event in session.events:
        print(f"   · {event}")


def _t13_print_sizes(cfg: T13Config) -> None:
    print("\n── ClientHello size estimate (ECH on, early data on) " + "─" * 8)
    print(f"   {'group':22} {'CH bytes':>9} {'segments':>9}  padding class")
    for group in (T13Group.X25519, T13Group.X25519_MLKEM768,
                  T13Group.X25519_MLKEM1024):
        est = t13_estimate_client_hello(
            group, sni_length=15, ech=True, early_data=True,
            classes=cfg.padding.classes,
        )
        print(f"   {group.label:22} {est.outer_padded:9} {est.segments:9}"
              f"  {est.padding_class}")


def t13_demo(config: T13Config | None = None) -> int:
    cfg = config or t13_default_hybrid()
    t13_validate(cfg)

    print("TLS 1.3 / TLS13-PQ demo")
    print(f"  profile      : {cfg.profile.value}")
    print(f"  groups       : {', '.join(g.label for g in cfg.groups.offered)}")
    print(f"  early data   : {cfg.early_data.mode.value}, "
          f"max_lifetime={t13_format_duration(cfg.early_data.max_lifetime)}")
    print(f"  replay       : {cfg.replay.ownership.value}/"
          f"{cfg.replay.filter.value}, fail_mode={cfg.replay.fail_mode.value}")
    print(f"  ECH          : {len(cfg.ech.keys)} configs, "
          f"key_ttl={t13_format_duration(cfg.ech.key_ttl)}, "
          f"public_name={cfg.ech.public_name}")

    _t13_print_sizes(cfg)

    sim = T13HandshakeSimulator(cfg)
    ticket = t13_demo_ticket(sim.now)
    hello = T13ClientHello()

    first = sim.process(hello, ticket)
    _t13_print_session("1. first 0-RTT flight", first)

    replay = sim.process(hello, ticket)
    _t13_print_session("2. byte-identical replay (filter active)", replay)

    missed = sim.process(hello, ticket, bypass_filter=True)
    _t13_print_session("3. replay with the filter deliberately bypassed", missed)

    expired_ticket = T13Ticket(
        nonce=b"\xB2" * 16,
        pq_epoch=1,
        issued_at=sim.now - timedelta(seconds=60),
        max_early_data=timedelta(seconds=10),
    )
    expired = sim.process(hello, expired_ticket)
    _t13_print_session("4. expired ticket", expired)

    legacy = sim.process(T13ClientHello(guard=False), ticket)
    _t13_print_session("5. legacy client (no early_data_guard)", legacy)

    print("\n── result " + "─" * 51)
    print(f"   application effects published: {len(sim.server.effects)}")
    print("   expected: 1. The replay in step 2 is filtered; the replay in")
    print("   step 3 gets past a bypassed filter but is deduplicated by the")
    print("   commit store. Steps 4 and 5 never reach commit.")
    assert len(sim.server.effects) == 1, "duplicate side effect!"
    assert missed.early_status is T13EarlyDataStatus.DEDUPED
    print("   OK")
    return 0


def t13_validate_command(path: str | None = None) -> int:
    try:
        if path:
            cfg = t13_load_config(path)
        else:
            cfg = t13_from_dict(T13_EXAMPLE_CONFIG)
    except (OSError, json.JSONDecodeError, T13ConfigError) as exc:
        print(f"INVALID  {path or '<beépített példa>'}\n  {exc}", file=sys.stderr)
        return 1

    print(f"OK       {path or '<beépített példa>'}")
    print(f"  profile      {cfg.profile.value}")
    print(f"  groups       {', '.join(g.label for g in cfg.groups.offered)}")
    print(f"  early_data   {cfg.early_data.mode.value}, "
          f"max_lifetime={t13_format_duration(cfg.early_data.max_lifetime)}")
    print(f"  replay       {cfg.replay.ownership.value}/{cfg.replay.filter.value}, "
          f"fail_mode={cfg.replay.fail_mode.value}")
    print(f"  commit       {cfg.commit.commit_point}, "
          f"linearizable={cfg.commit.linearizable}")
    print(f"  ech          {len(cfg.ech.keys)} configs, "
          f"key_ttl={t13_format_duration(cfg.ech.key_ttl)}, "
          f"retry_grace={t13_format_duration(cfg.ech.retry_grace)}")
    print(f"  padding      {cfg.padding.classes}")
    return 0


def t13_selftest() -> int:
    # 1. Az alapértelmezett és a beépített példakonfiguráció is érvényes.
    t13_validate(t13_default_hybrid())
    cfg = t13_from_dict(T13_EXAMPLE_CONFIG)
    t13_validate(cfg)

    # 2. Ismeretlen mező = hiba.
    bad = json.loads(json.dumps(T13_EXAMPLE_CONFIG))
    bad["groups"]["failmode"] = "open"
    try:
        t13_from_dict(bad)
    except T13ConfigError:
        pass
    else:
        raise AssertionError("unknown field accepted")

    # 3. strict-pq invariánsok.
    strict = t13_default_hybrid()
    strict.profile = T13Profile.STRICT_PQ
    strict.auth.require_pq_signature = True
    strict.groups.require_pq = True
    strict.ech.allow_plaintext_fallback = False
    strict.commit.commit_point = "on_send"
    t13_validate(strict)
    strict.auth.require_pq_signature = False
    try:
        t13_validate(strict)
    except T13ConfigError:
        pass
    else:
        raise AssertionError("strict-pq invariant not enforced")

    # 4. Replay filter és commit store.
    now = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
    ticket = t13_demo_ticket(now)
    server = T13Server()
    assert server.accept_early_data(ticket, now) is T13EarlyDataStatus.ACCEPTED
    assert server.accept_early_data(ticket, now) is T13EarlyDataStatus.REJECTED_REPLAY

    server2 = T13Server()
    first = server2.handle(ticket, b"token", now)
    second = server2.handle(ticket, b"token", now, bypass_filter=True)
    assert first.status is T13EarlyDataStatus.ACCEPTED
    assert second.status is T13EarlyDataStatus.DEDUPED
    assert len(server2.effects) == 1

    # 5. Szimulátor: 5 lépés, pontosan 1 mellékhatás.
    sim = T13HandshakeSimulator(t13_default_hybrid())
    hello = T13ClientHello()
    t = t13_demo_ticket(sim.now)
    sim.process(hello, t)
    sim.process(hello, t)
    deduped = sim.process(hello, t, bypass_filter=True)
    sim.process(hello, T13Ticket(nonce=b"\xB2" * 16, pq_epoch=1,
                                 issued_at=sim.now - timedelta(seconds=60)))
    sim.process(T13ClientHello(guard=False), t)
    assert len(sim.server.effects) == 1
    assert deduped.early_status is T13EarlyDataStatus.DEDUPED

    # 6. Padding osztályok monoton nőnek; a méret nem függ az SNI-től.
    classes = cfg.padding.classes
    for group in (T13Group.X25519, T13Group.X25519_MLKEM768):
        a = t13_estimate_client_hello(group, 10, ech=True, early_data=True,
                                      classes=classes)
        b = t13_estimate_client_hello(group, 60, ech=True, early_data=True,
                                      classes=classes)
        assert a.outer_padded == b.outer_padded

    # 7. JSON roundtrip.
    assert t13_to_dict(t13_from_dict(t13_to_dict(cfg))) == t13_to_dict(cfg)

    print("TLS 1.3 selftest: OK (konfiguráció, replay, dedup, padding, roundtrip)")
    return 0


# ===========================================================================
# TLS 1.4 -- hibrid X25519 + RSA-OAEP, saját protokolltervezet
# ===========================================================================
#
# A TLS 1.4 C++/OpenSSL implementáció Python portja. A wire-format és a
# kulcsderiválás hűen követi a docs/PROTOCOL.md leírását. A tanúsítvány-
# ellenőrzés a cryptography X.509 modelljére épül, de a láncépítés és a
# keyUsage/EKU/SAN ellenőrzés saját (a C++ viselkedését követő) kód.
# ===========================================================================

T14_VERSION = 0x0305
T14_LEGACY_VERSION = 0x0303
T14_GROUP_X25519 = 0x001D

T14_HS_CLIENT_HELLO = 1
T14_HS_SERVER_HELLO = 2
T14_HS_NEW_SESSION_TICKET = 4
T14_HS_END_OF_EARLY_DATA = 5
T14_HS_ENCRYPTED_EXTENSIONS = 8
T14_HS_CERTIFICATE = 11
T14_HS_CERTIFICATE_REQUEST = 13
T14_HS_SERVER_HELLO_DONE = 14
T14_HS_CERTIFICATE_VERIFY = 15
T14_HS_FINISHED = 20
T14_HS_KEY_UPDATE = 24
T14_HS_HYBRID_CLIENT_KEY_EXCHANGE = 0x1C

T14_RSA_OAEP_SHA256 = 0x01

T14_CT_CHANGE_CIPHER_SPEC = 20
T14_CT_ALERT = 21
T14_CT_HANDSHAKE = 22
T14_CT_APPLICATION_DATA = 23

T14_EXT_SERVER_NAME = 0x0000
T14_EXT_SUPPORTED_GROUPS = 0x000A
T14_EXT_SIGNATURE_ALGORITHMS = 0x000D
T14_EXT_ALPN = 0x0010
T14_EXT_SUPPORTED_VERSIONS = 0x002B
T14_EXT_KEY_SHARE = 0x0033
T14_EXT_HYBRID_RSA_KEM = 0xFF01

T14_ALERT_WARNING = 1
T14_ALERT_FATAL = 2

T14_ALERT_CLOSE_NOTIFY = 0
T14_ALERT_UNEXPECTED_MESSAGE = 10
T14_ALERT_BAD_RECORD_MAC = 20
T14_ALERT_RECORD_OVERFLOW = 22
T14_ALERT_HANDSHAKE_FAILURE = 40
T14_ALERT_BAD_CERTIFICATE = 42
T14_ALERT_UNSUPPORTED_CERTIFICATE = 43
T14_ALERT_CERTIFICATE_REVOKED = 44
T14_ALERT_CERTIFICATE_UNKNOWN = 46
T14_ALERT_ILLEGAL_PARAMETER = 47
T14_ALERT_UNKNOWN_CA = 48
T14_ALERT_DECODE_ERROR = 50
T14_ALERT_DECRYPT_ERROR = 51
T14_ALERT_PROTOCOL_VERSION = 70
T14_ALERT_INTERNAL_ERROR = 80
T14_ALERT_MISSING_EXTENSION = 109
T14_ALERT_UNSUPPORTED_EXTENSION = 110
T14_ALERT_CERTIFICATE_REQUIRED = 116
T14_ALERT_NO_APPLICATION_PROTOCOL = 120

T14_MAX_PLAINTEXT = 1 << 14
T14_MAX_CIPHERTEXT = T14_MAX_PLAINTEXT + 256
T14_MAX_AES_GCM_RECORDS = 23726566  # 2^24.5
T14_MAX_HANDSHAKE_BUFFER = 1 << 20


class T14Error(Exception):
    pass


class T14Alert(T14Error):
    def __init__(self, description: int, what: str):
        super().__init__(what)
        self.description = description


class T14ConnectionClosed(T14Error):
    def __init__(self) -> None:
        super().__init__("connection closed")


class T14Hash(Enum):
    SHA256 = "sha256"
    SHA384 = "sha384"


class T14Suite(IntEnum):
    AES_128_GCM_SHA256 = 0x1301
    AES_256_GCM_SHA384 = 0x1302


class T14SignatureScheme(IntEnum):
    RSA_PSS_RSAE_SHA256 = 0x0804
    RSA_PSS_RSAE_SHA384 = 0x0805
    ECDSA_SECP256R1_SHA256 = 0x0403


T14_DEFAULT_SIGNATURE_SCHEMES = [
    T14SignatureScheme.RSA_PSS_RSAE_SHA256,
    T14SignatureScheme.RSA_PSS_RSAE_SHA384,
    T14SignatureScheme.ECDSA_SECP256R1_SHA256,
]


# ---------------------------------------------------------------------------
# T14: hash, HMAC, HKDF
# ---------------------------------------------------------------------------


def t14_hash_length(h: T14Hash) -> int:
    return 32 if h is T14Hash.SHA256 else 48


def t14_hash_alg(h: T14Hash):
    return hashes.SHA256() if h is T14Hash.SHA256 else hashes.SHA384()


def t14_suite_hash(suite: T14Suite) -> T14Hash:
    if suite is T14Suite.AES_128_GCM_SHA256:
        return T14Hash.SHA256
    return T14Hash.SHA384


def t14_suite_key_length(suite: T14Suite) -> int:
    return 16 if suite is T14Suite.AES_128_GCM_SHA256 else 32


def t14_suite_name(suite: T14Suite) -> str:
    if suite is T14Suite.AES_128_GCM_SHA256:
        return "TLS_AES_128_GCM_SHA256"
    return "TLS_AES_256_GCM_SHA384"


def t14_is_supported_suite(value: int) -> bool:
    return value in (int(T14Suite.AES_128_GCM_SHA256),
                     int(T14Suite.AES_256_GCM_SHA384))


def t14_is_supported_signature_scheme(value: int) -> bool:
    return value in {int(s) for s in T14SignatureScheme}


def t14_random_bytes(n: int) -> bytes:
    return os.urandom(n)


def t14_digest(h: T14Hash, data: bytes) -> bytes:
    return hashlib.new(h.value, data).digest()


def t14_hmac(h: T14Hash, key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, h.value).digest()


def t14_hkdf_extract(h: T14Hash, salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * t14_hash_length(h)
    return t14_hmac(h, salt, ikm)


def t14_hkdf_expand(h: T14Hash, prk: bytes, info: bytes,
                    length: int) -> bytes:
    hlen = t14_hash_length(h)
    if length > 255 * hlen:
        raise T14Error("hkdf_expand: requested length exceeds 255*HashLen")
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = t14_hmac(h, prk, t + info + bytes([counter]))
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def t14_hkdf_expand_label(h: T14Hash, secret: bytes, label: bytes,
                          context: bytes, length: int) -> bytes:
    if length > 0xFFFF:
        raise T14Error("hkdf_expand_label: length does not fit uint16")
    full_label = b"tls14 " + label
    if len(full_label) > 255:
        raise T14Error("hkdf_expand_label: label too long")
    if len(context) > 255:
        raise T14Error("hkdf_expand_label: context too long")
    info = (struct.pack(">H", length)
            + bytes([len(full_label)]) + full_label
            + bytes([len(context)]) + context)
    return t14_hkdf_expand(h, secret, info, length)


def t14_derive_secret(h: T14Hash, secret: bytes, label: bytes,
                      transcript_hash: bytes) -> bytes:
    if len(transcript_hash) != t14_hash_length(h):
        raise T14Error("derive_secret: bad transcript hash length")
    return t14_hkdf_expand_label(h, secret, label, transcript_hash,
                                 t14_hash_length(h))


def t14_finished_verify_data(h: T14Hash, base_key: bytes,
                             transcript_hash: bytes) -> bytes:
    if len(transcript_hash) != t14_hash_length(h):
        raise T14Error("finished_verify_data: bad transcript hash length")
    finished_key = t14_hkdf_expand_label(
        h, base_key, b"finished", b"", t14_hash_length(h)
    )
    return t14_hmac(h, finished_key, transcript_hash)


def t14_next_traffic_secret(h: T14Hash, current_secret: bytes) -> bytes:
    return t14_hkdf_expand_label(h, current_secret, b"traffic upd", b"",
                                 t14_hash_length(h))


# ---------------------------------------------------------------------------
# T14: kulcscsere és aláírások
# ---------------------------------------------------------------------------


def t14_x25519_generate():
    _require_crypto()
    return x25519.X25519PrivateKey.generate()


def t14_x25519_public(private_key) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def t14_x25519_derive(private_key, peer_public: bytes) -> bytes:
    if len(peer_public) != 32:
        raise T14Error("X25519 peer public key must be 32 bytes")
    peer = x25519.X25519PublicKey.from_public_bytes(peer_public)
    shared = private_key.exchange(peer)
    if not any(shared):
        raise T14Error("X25519: all-zero shared secret")
    return shared


def t14_rsa_oaep_encrypt(public_key, message: bytes) -> bytes:
    return public_key.encrypt(
        message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def t14_rsa_oaep_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def t14_scheme_compatible(key: Any, scheme: T14SignatureScheme) -> bool:
    if key is None:
        return False
    if scheme in (T14SignatureScheme.RSA_PSS_RSAE_SHA256,
                  T14SignatureScheme.RSA_PSS_RSAE_SHA384):
        return isinstance(key, rsa.RSAPrivateKey) or isinstance(
            key, rsa.RSAPublicKey
        )
    if scheme is T14SignatureScheme.ECDSA_SECP256R1_SHA256:
        if isinstance(key, ec.EllipticCurvePrivateKey):
            return isinstance(key.curve, ec.SECP256R1)
        if isinstance(key, ec.EllipticCurvePublicKey):
            return isinstance(key.curve, ec.SECP256R1)
    return False


def _t14_signature_params(scheme: T14SignatureScheme):
    if scheme is T14SignatureScheme.RSA_PSS_RSAE_SHA256:
        return T14Hash.SHA256, True
    if scheme is T14SignatureScheme.RSA_PSS_RSAE_SHA384:
        return T14Hash.SHA384, True
    if scheme is T14SignatureScheme.ECDSA_SECP256R1_SHA256:
        return T14Hash.SHA256, False
    raise T14Error("unknown signature scheme")


def t14_choose_signature_scheme(key: Any, offered: list[T14SignatureScheme],
                                preferred_hash: T14Hash) -> T14SignatureScheme:
    for scheme in offered:
        if (t14_scheme_compatible(key, scheme)
                and _t14_signature_params(scheme)[0] is preferred_hash):
            return scheme
    for scheme in offered:
        if t14_scheme_compatible(key, scheme):
            return scheme
    raise T14Error("no compatible signature scheme offered by the peer")


def t14_sign_with_scheme(key: Any, scheme: T14SignatureScheme,
                         data: bytes) -> bytes:
    if not t14_scheme_compatible(key, scheme):
        raise T14Error("signature scheme is not compatible with the key")
    h, pss = _t14_signature_params(scheme)
    alg = t14_hash_alg(h)
    if pss:
        return key.sign(
            data,
            asym_padding.PSS(mgf=asym_padding.MGF1(alg),
                             salt_length=alg.digest_size),
            alg,
        )
    return key.sign(data, ec.ECDSA(alg))


def t14_verify_with_scheme(key: Any, scheme: T14SignatureScheme,
                           data: bytes, signature: bytes) -> bool:
    if not t14_scheme_compatible(key, scheme):
        return False
    h, pss = _t14_signature_params(scheme)
    alg = t14_hash_alg(h)
    try:
        if pss:
            key.verify(
                signature,
                data,
                asym_padding.PSS(mgf=asym_padding.MGF1(alg),
                                 salt_length=alg.digest_size),
                alg,
            )
        else:
            key.verify(signature, data, ec.ECDSA(alg))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# T14: AES-GCM és nonce
# ---------------------------------------------------------------------------


def t14_aes_gcm_seal(key: bytes, nonce: bytes, aad: bytes,
                     plaintext: bytes) -> bytes:
    if len(key) not in (16, 32):
        raise T14Error("aes_gcm_seal: key must be 16 or 32 bytes")
    if len(nonce) != 12:
        raise T14Error("aes_gcm_seal: nonce must be 12 bytes")
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def t14_aes_gcm_open(key: bytes, nonce: bytes, aad: bytes,
                     ciphertext: bytes) -> bytes:
    if len(key) not in (16, 32):
        raise T14Error("aes_gcm_open: key must be 16 or 32 bytes")
    if len(nonce) != 12:
        raise T14Error("aes_gcm_open: nonce must be 12 bytes")
    if len(ciphertext) < 16:
        raise T14Error("aes_gcm_open: ciphertext shorter than tag")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise T14Error("AES-GCM authentication failed") from exc


def t14_make_nonce(iv: bytes, sequence_number: int) -> bytes:
    if len(iv) != 12:
        raise T14Error("make_nonce: IV must be 12 bytes")
    nonce = bytearray(iv)
    for i in range(8):
        nonce[11 - i] ^= (sequence_number >> (8 * i)) & 0xFF
    return bytes(nonce)


# ---------------------------------------------------------------------------
# T14: PEM betöltés
# ---------------------------------------------------------------------------


def t14_load_private_key(path: str) -> Any:
    _require_crypto()
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def t14_load_certificate_chain_der(path: str) -> list[bytes]:
    _require_crypto()
    data = Path(path).read_text(encoding="ascii")
    certs: list[bytes] = []
    marker = "-----BEGIN CERTIFICATE-----"
    for block in data.split(marker)[1:]:
        pem = marker + block.split("-----END CERTIFICATE-----", 1)[0] + \
            "-----END CERTIFICATE-----\n"
        cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
        certs.append(cert.public_bytes(serialization.Encoding.DER))
    if not certs:
        raise T14Error("no certificates found in " + path)
    return certs


# ---------------------------------------------------------------------------
# T14: wire encoding
# ---------------------------------------------------------------------------


def t14_append_u8(out: bytearray, value: int) -> None:
    out.append(value & 0xFF)


def t14_append_u16(out: bytearray, value: int) -> None:
    out.extend(struct.pack(">H", value))


def t14_append_u24(out: bytearray, value: int) -> None:
    if value > 0xFFFFFF:
        raise T14Error("append_u24: value too large")
    out.extend(value.to_bytes(3, "big"))


def t14_append_u32(out: bytearray, value: int) -> None:
    out.extend(struct.pack(">I", value))


def t14_append_u64(out: bytearray, value: int) -> None:
    out.extend(struct.pack(">Q", value))


def t14_append_vec8(out: bytearray, value: bytes) -> None:
    if len(value) > 0xFF:
        raise T14Error("append_vec8: value too long")
    out.append(len(value))
    out.extend(value)


def t14_append_vec16(out: bytearray, value: bytes) -> None:
    if len(value) > 0xFFFF:
        raise T14Error("append_vec16: value too long")
    out.extend(struct.pack(">H", len(value)))
    out.extend(value)


def t14_append_vec24(out: bytearray, value: bytes) -> None:
    if len(value) > 0xFFFFFF:
        raise T14Error("append_vec24: value too long")
    out.extend(len(value).to_bytes(3, "big"))
    out.extend(value)


class T14Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def u8(self) -> int:
        if self.remaining() < 1:
            raise T14Error("Reader: truncated uint8")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def u16(self) -> int:
        if self.remaining() < 2:
            raise T14Error("Reader: truncated uint16")
        value = struct.unpack_from(">H", self.data, self.pos)[0]
        self.pos += 2
        return value

    def u24(self) -> int:
        if self.remaining() < 3:
            raise T14Error("Reader: truncated uint24")
        value = int.from_bytes(self.data[self.pos:self.pos + 3], "big")
        self.pos += 3
        return value

    def u32(self) -> int:
        if self.remaining() < 4:
            raise T14Error("Reader: truncated uint32")
        value = struct.unpack_from(">I", self.data, self.pos)[0]
        self.pos += 4
        return value

    def u64(self) -> int:
        if self.remaining() < 8:
            raise T14Error("Reader: truncated uint64")
        value = struct.unpack_from(">Q", self.data, self.pos)[0]
        self.pos += 8
        return value

    def bytes(self, n: int) -> bytes:
        if n > self.remaining():
            raise T14Error("Reader: truncated byte string")
        value = self.data[self.pos:self.pos + n]
        self.pos += n
        return value

    def vec8(self) -> bytes:
        return self.bytes(self.u8())

    def vec16(self) -> bytes:
        return self.bytes(self.u16())

    def vec24(self) -> bytes:
        return self.bytes(self.u24())

    def rest(self) -> bytes:
        return self.bytes(self.remaining())

    def require_end(self) -> None:
        if self.pos != len(self.data):
            raise T14Error("Reader: trailing bytes")


@dataclass
class T14HandshakeMessage:
    type: int = 0
    body: bytes = b""

    def encode(self) -> bytes:
        if len(self.body) > 0xFFFFFF:
            raise T14Error("HandshakeMessage: body too long")
        out = bytearray()
        t14_append_u8(out, self.type)
        t14_append_u24(out, len(self.body))
        out.extend(self.body)
        return bytes(out)

    @classmethod
    def decode(cls, message: bytes) -> "T14HandshakeMessage":
        r = T14Reader(message)
        msg_type = r.u8()
        length = r.u24()
        if length != r.remaining():
            raise T14Error("HandshakeMessage: bad length")
        body = r.bytes(length)
        r.require_end()
        return cls(msg_type, body)


# ---------------------------------------------------------------------------
# T14: X.509 lánc, ellenőrzés
# ---------------------------------------------------------------------------


@dataclass
class T14CertificateChain:
    request_context: bytes = b""
    certificates: list[bytes] = field(default_factory=list)

    def encode(self) -> bytes:
        body = bytearray()
        t14_append_vec8(body, self.request_context)
        entries = bytearray()
        for cert in self.certificates:
            t14_append_vec24(entries, cert)
            t14_append_u16(entries, 0)  # nincs per-certificate extension
        t14_append_vec24(body, bytes(entries))
        return T14HandshakeMessage(T14_HS_CERTIFICATE, bytes(body)).encode()

    @classmethod
    def decode(cls, message: bytes) -> "T14CertificateChain":
        msg = T14HandshakeMessage.decode(message)
        if msg.type != T14_HS_CERTIFICATE:
            raise T14Error("CertificateChain: not a Certificate message")
        r = T14Reader(msg.body)
        context = r.vec8()
        entries = r.vec24()
        r.require_end()
        out = cls(request_context=context)
        er = T14Reader(entries)
        while er.remaining() > 0:
            cert = er.vec24()
            if not cert:
                raise T14Error("CertificateChain: empty certificate entry")
            er.vec16()  # per-certificate extensions (figyelmen kívül)
            out.certificates.append(cert)
        return out


def t14_certificate_leaf_public_key(chain: T14CertificateChain) -> Any:
    if not chain.certificates:
        raise T14Error("certificate chain is empty")
    cert = x509.load_der_x509_certificate(chain.certificates[0])
    return cert.public_key()


def t14_certificate_matches_private_key(chain: T14CertificateChain,
                                        key: Any) -> bool:
    if not chain.certificates or key is None:
        return False
    try:
        cert = x509.load_der_x509_certificate(chain.certificates[0])
        leaf = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        own = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hmac.compare_digest(leaf, own)
    except Exception:
        return False


def _t14_cert_time(cert: Any, name: str) -> datetime:
    utc_value = getattr(cert, name + "_utc", None)
    if utc_value is not None:
        return utc_value
    value = getattr(cert, name)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _t14_cert_extension(cert: Any, cls: type) -> Any:
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def _t14_check_validity(cert: Any) -> None:
    now = datetime.now(timezone.utc)
    if now < _t14_cert_time(cert, "not_valid_before"):
        raise T14Error("certificate verification failed: certificate not yet valid")
    if now > _t14_cert_time(cert, "not_valid_after"):
        raise T14Error("certificate verification failed: certificate expired")


def _t14_check_ca(cert: Any) -> None:
    bc = _t14_cert_extension(cert, x509.BasicConstraints)
    if bc is None or not bc.ca:
        raise T14Error("certificate verification failed: issuer is not a CA")
    ku = _t14_cert_extension(cert, x509.KeyUsage)
    if ku is not None and not ku.key_cert_sign:
        raise T14Error(
            "certificate verification failed: CA lacks keyCertSign"
        )


def _t14_verify_cert_signature(cert: Any, issuer: Any) -> bool:
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            try:
                key.verify(cert.signature, cert.tbs_certificate_bytes,
                           asym_padding.PKCS1v15(),
                           cert.signature_hash_algorithm)
            except InvalidSignature:
                alg = cert.signature_hash_algorithm
                key.verify(cert.signature, cert.tbs_certificate_bytes,
                           asym_padding.PSS(
                               mgf=asym_padding.MGF1(alg),
                               salt_length=alg.digest_size,
                           ),
                           alg)
            return True
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes,
                       ec.ECDSA(cert.signature_hash_algorithm))
            return True
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes)
            return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    return False


def _t14_dns_match(pattern: str, hostname: str) -> bool:
    if pattern == hostname:
        return True
    if not pattern.startswith("*.") or "*" in pattern[2:]:
        return False
    suffix = pattern[2:]
    if "." not in suffix:
        return False
    if not hostname.endswith("." + suffix):
        return False
    prefix = hostname[:-(len(suffix) + 1)]
    return bool(prefix) and "." not in prefix


def _t14_hostname_matches(cert: Any, hostname: str) -> bool:
    san = _t14_cert_extension(cert, x509.SubjectAlternativeName)
    try:
        wanted_ip = ipaddress.ip_address(hostname)
    except ValueError:
        wanted_ip = None

    if wanted_ip is not None:
        if san is not None:
            for addr in san.get_values_for_type(x509.IPAddress):
                if addr == wanted_ip:
                    return True
            return False
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            try:
                if ipaddress.ip_address(attr.value) == wanted_ip:
                    return True
            except ValueError:
                pass
        return False

    host = hostname.lower().rstrip(".")
    if san is not None:
        names = [n.lower().rstrip(".")
                 for n in san.get_values_for_type(x509.DNSName)]
    else:
        names = [a.value.lower().rstrip(".")
                 for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return any(_t14_dns_match(pattern, host) for pattern in names)


class T14CertificateVerifier:
    """A C++ CertificateVerifier Python megfelelője.

    A láncot a megadott CA-készletig építi, ellenőrzi az aláírásokat, a
    lejáratot, a CA basicConstraints/keyUsage bitet, a levél keyUsage/EKU
    követelményeit és a hostname/IP SAN egyezést.
    """

    def __init__(self, ca_chain: list[bytes]):
        if not ca_chain:
            raise T14Error("CA store is empty")
        self.trusted = [x509.load_der_x509_certificate(der) for der in ca_chain]
        self._trusted_ders = {
            cert.public_bytes(serialization.Encoding.DER)
            for cert in self.trusted
        }

    def verify_server(self, chain: T14CertificateChain,
                      hostname: str) -> None:
        self._verify_chain(chain, hostname, "server", True)

    def verify_client(self, chain: T14CertificateChain) -> None:
        self._verify_chain(chain, "", "client", False)

    def leaf_public_key(self, chain: T14CertificateChain) -> Any:
        return t14_certificate_leaf_public_key(chain)

    def _verify_chain(self, chain: T14CertificateChain, hostname: str,
                      purpose: str, require_key_encipherment: bool) -> None:
        if not chain.certificates:
            raise T14Error("certificate verification failed: empty chain")
        try:
            certs = [x509.load_der_x509_certificate(der)
                     for der in chain.certificates]
        except ValueError as exc:
            raise T14Error(f"certificate verification failed: {exc}") from exc
        leaf = certs[0]

        ku = _t14_cert_extension(leaf, x509.KeyUsage)
        if ku is None or not ku.digital_signature:
            raise T14Error(
                "leaf certificate lacks keyUsage=digitalSignature"
            )
        if require_key_encipherment and not ku.key_encipherment:
            raise T14Error(
                "leaf certificate lacks keyUsage=keyEncipherment"
            )
        eku = _t14_cert_extension(leaf, x509.ExtendedKeyUsage)
        required = (ExtendedKeyUsageOID.SERVER_AUTH
                    if purpose == "server" else ExtendedKeyUsageOID.CLIENT_AUTH)
        any_eku = x509.ObjectIdentifier("2.5.29.37.0")
        if eku is None or (required not in eku and any_eku not in eku):
            raise T14Error(
                "leaf certificate lacks the required extendedKeyUsage"
            )

        _t14_check_validity(leaf)
        if hostname and not _t14_hostname_matches(leaf, hostname):
            raise T14Error(
                "certificate verification failed: hostname mismatch"
            )

        current = leaf
        pool = list(certs[1:])
        for _ in range(10):
            current_der = current.public_bytes(serialization.Encoding.DER)
            if current_der in self._trusted_ders:
                return

            issuer = None
            for index, candidate in enumerate(pool):
                if candidate.subject == current.issuer:
                    if _t14_verify_cert_signature(current, candidate):
                        issuer = pool.pop(index)
                        break
            if issuer is None:
                for candidate in self.trusted:
                    if candidate.subject == current.issuer:
                        if _t14_verify_cert_signature(current, candidate):
                            issuer = candidate
                            break
            if issuer is None:
                raise T14Error(
                    "certificate verification failed: unable to build chain"
                )
            _t14_check_ca(issuer)
            _t14_check_validity(issuer)
            issuer_der = issuer.public_bytes(serialization.Encoding.DER)
            if issuer_der in self._trusted_ders:
                return
            if issuer in pool:
                pool.remove(issuer)
            current = issuer
        raise T14Error("certificate verification failed: chain too long")


# ---------------------------------------------------------------------------
# T14: extensionök és handshake-üzenetek
# ---------------------------------------------------------------------------


@dataclass
class T14Extension:
    type: int = 0
    data: bytes = b""


@dataclass
class T14KeyShareEntry:
    group: int = 0
    key_exchange: bytes = b""


def t14_encode_extensions(extensions: list[T14Extension]) -> bytes:
    out = bytearray()
    for ext in extensions:
        t14_append_u16(out, ext.type)
        t14_append_vec16(out, ext.data)
    return bytes(out)


def t14_decode_extensions(data: bytes) -> list[T14Extension]:
    r = T14Reader(data)
    out: list[T14Extension] = []
    while r.remaining() > 0:
        out.append(T14Extension(r.u16(), r.vec16()))
    return out


def t14_find_extension(extensions: list[T14Extension],
                       ext_type: int) -> T14Extension | None:
    for ext in extensions:
        if ext.type == ext_type:
            return ext
    return None


def t14_parse_key_share_list(data: bytes) -> list[T14KeyShareEntry]:
    r = T14Reader(data)
    entries = r.vec16()
    r.require_end()
    er = T14Reader(entries)
    out: list[T14KeyShareEntry] = []
    while er.remaining() > 0:
        out.append(T14KeyShareEntry(er.u16(), er.vec16()))
    return out


def t14_parse_key_share_single(data: bytes) -> T14KeyShareEntry:
    r = T14Reader(data)
    entry = T14KeyShareEntry(r.u16(), r.vec16())
    r.require_end()
    return entry


def t14_parse_u16_list(data: bytes) -> list[int]:
    r = T14Reader(data)
    entries = r.vec16()
    r.require_end()
    if len(entries) % 2 != 0:
        raise T14Error("bad uint16 list")
    er = T14Reader(entries)
    out: list[int] = []
    while er.remaining() > 0:
        out.append(er.u16())
    return out


def t14_parse_supported_versions_client(data: bytes) -> list[int]:
    r = T14Reader(data)
    entries = r.vec8()
    r.require_end()
    if len(entries) % 2 != 0:
        raise T14Error("bad supported_versions list")
    er = T14Reader(entries)
    out: list[int] = []
    while er.remaining() > 0:
        out.append(er.u16())
    return out


def t14_parse_signature_algorithms(data: bytes) -> list[T14SignatureScheme]:
    return [T14SignatureScheme(v) for v in t14_parse_u16_list(data)
            if t14_is_supported_signature_scheme(v)]


def t14_parse_server_name(data: bytes) -> str:
    r = T14Reader(data)
    entries = r.vec16()
    r.require_end()
    er = T14Reader(entries)
    while er.remaining() > 0:
        name_type = er.u8()
        name = er.vec16()
        if name_type == 0:
            return name.decode("utf-8", "replace")
    return ""


def t14_parse_alpn(data: bytes) -> list[str]:
    r = T14Reader(data)
    entries = r.vec16()
    r.require_end()
    er = T14Reader(entries)
    out: list[str] = []
    while er.remaining() > 0:
        name = er.vec8()
        if not name:
            raise T14Error("ALPN: empty protocol name")
        out.append(name.decode("utf-8", "replace"))
    return out


def t14_make_supported_versions_client() -> bytes:
    list_data = struct.pack(">H", T14_VERSION)
    out = bytearray()
    t14_append_vec8(out, list_data)
    return bytes(out)


def t14_make_supported_versions_server() -> bytes:
    return struct.pack(">H", T14_VERSION)


def t14_make_key_share_client(group: int, public_key: bytes) -> bytes:
    entry = bytearray()
    t14_append_u16(entry, group)
    t14_append_vec16(entry, public_key)
    out = bytearray()
    t14_append_vec16(out, bytes(entry))
    return bytes(out)


def t14_make_key_share_server(group: int, public_key: bytes) -> bytes:
    out = bytearray()
    t14_append_u16(out, group)
    t14_append_vec16(out, public_key)
    return bytes(out)


def t14_make_signature_algorithms(
        schemes: list[T14SignatureScheme]) -> bytes:
    list_data = bytearray()
    for scheme in schemes:
        t14_append_u16(list_data, int(scheme))
    out = bytearray()
    t14_append_vec16(out, bytes(list_data))
    return bytes(out)


def t14_make_server_name(hostname: str) -> bytes:
    if not hostname or len(hostname) > 0xFFFF:
        raise T14Error("invalid server name")
    entry = bytearray()
    t14_append_u8(entry, 0)
    t14_append_vec16(entry, hostname.encode("utf-8"))
    out = bytearray()
    t14_append_vec16(out, bytes(entry))
    return bytes(out)


def t14_make_alpn(protocols: list[str]) -> bytes:
    if not protocols:
        raise T14Error("ALPN: empty protocol list")
    list_data = bytearray()
    for protocol in protocols:
        data = protocol.encode("utf-8")
        if not data or len(data) > 0xFF:
            raise T14Error("ALPN: invalid protocol name")
        t14_append_vec8(list_data, data)
    out = bytearray()
    t14_append_vec16(out, bytes(list_data))
    return bytes(out)


def t14_make_supported_groups(groups: list[int]) -> bytes:
    list_data = bytearray()
    for group in groups:
        t14_append_u16(list_data, group)
    out = bytearray()
    t14_append_vec16(out, bytes(list_data))
    return bytes(out)


def t14_make_hybrid_rsa_kem_offer() -> bytes:
    out = bytearray()
    t14_append_u16(out, 1)  # hybrid bundle version
    t14_append_u8(out, 1)   # inline mode
    return bytes(out)


@dataclass
class T14ClientHello:
    legacy_version: int = T14_LEGACY_VERSION
    random: bytes = b""
    session_id: bytes = b""
    cipher_suites: list[T14Suite] = field(default_factory=list)
    extensions: list[T14Extension] = field(default_factory=list)

    def encode(self) -> bytes:
        if len(self.random) != 32:
            raise T14Error("ClientHello: random must be 32 bytes")
        if len(self.session_id) > 32:
            raise T14Error("ClientHello: session id too long")
        body = bytearray()
        t14_append_u16(body, self.legacy_version)
        body.extend(self.random)
        t14_append_vec8(body, self.session_id)
        suites = bytearray()
        if not self.cipher_suites:
            raise T14Error("ClientHello: no cipher suites")
        for suite in self.cipher_suites:
            t14_append_u16(suites, int(suite))
        t14_append_vec16(body, bytes(suites))
        t14_append_u8(body, 1)
        t14_append_u8(body, 0)
        t14_append_vec16(body, t14_encode_extensions(self.extensions))
        return T14HandshakeMessage(T14_HS_CLIENT_HELLO, bytes(body)).encode()

    @classmethod
    def decode(cls, message: bytes) -> "T14ClientHello":
        msg = T14HandshakeMessage.decode(message)
        if msg.type != T14_HS_CLIENT_HELLO:
            raise T14Error("not a ClientHello")
        r = T14Reader(msg.body)
        out = cls()
        out.legacy_version = r.u16()
        if out.legacy_version != T14_LEGACY_VERSION:
            raise T14Error("ClientHello: bad legacy_version")
        out.random = r.bytes(32)
        out.session_id = r.vec8()
        if len(out.session_id) > 32:
            raise T14Error("ClientHello: session id too long")
        suites = T14Reader(r.vec16())
        out.cipher_suites = []
        while suites.remaining() > 0:
            value = suites.u16()
            if t14_is_supported_suite(value):
                out.cipher_suites.append(T14Suite(value))
        compression = r.vec8()
        if not compression:
            raise T14Error("ClientHello: missing compression methods")
        if 0 not in compression:
            raise T14Error("ClientHello: null compression not offered")
        out.extensions = t14_decode_extensions(r.vec16())
        r.require_end()
        return out


@dataclass
class T14ServerHello:
    legacy_version: int = T14_LEGACY_VERSION
    random: bytes = b""
    session_id_echo: bytes = b""
    cipher_suite: T14Suite = T14Suite.AES_128_GCM_SHA256
    extensions: list[T14Extension] = field(default_factory=list)

    def encode(self) -> bytes:
        if len(self.random) != 32:
            raise T14Error("ServerHello: random must be 32 bytes")
        body = bytearray()
        t14_append_u16(body, self.legacy_version)
        body.extend(self.random)
        t14_append_vec8(body, self.session_id_echo)
        t14_append_u16(body, int(self.cipher_suite))
        t14_append_u8(body, 0)
        t14_append_vec16(body, t14_encode_extensions(self.extensions))
        return T14HandshakeMessage(T14_HS_SERVER_HELLO, bytes(body)).encode()

    @classmethod
    def decode(cls, message: bytes) -> "T14ServerHello":
        msg = T14HandshakeMessage.decode(message)
        if msg.type != T14_HS_SERVER_HELLO:
            raise T14Error("not a ServerHello")
        r = T14Reader(msg.body)
        out = cls()
        out.legacy_version = r.u16()
        if out.legacy_version != T14_LEGACY_VERSION:
            raise T14Error("ServerHello: bad legacy_version")
        out.random = r.bytes(32)
        out.session_id_echo = r.vec8()
        suite = r.u16()
        if not t14_is_supported_suite(suite):
            raise T14Error("ServerHello: unsupported cipher suite")
        out.cipher_suite = T14Suite(suite)
        if r.u8() != 0:
            raise T14Error("ServerHello: bad compression method")
        out.extensions = t14_decode_extensions(r.vec16())
        r.require_end()
        return out


@dataclass
class T14EncryptedExtensions:
    extensions: list[T14Extension] = field(default_factory=list)

    def encode(self) -> bytes:
        body = bytearray()
        t14_append_vec16(body, t14_encode_extensions(self.extensions))
        return T14HandshakeMessage(T14_HS_ENCRYPTED_EXTENSIONS,
                                   bytes(body)).encode()

    @classmethod
    def decode(cls, message: bytes) -> "T14EncryptedExtensions":
        msg = T14HandshakeMessage.decode(message)
        if msg.type != T14_HS_ENCRYPTED_EXTENSIONS:
            raise T14Error("not an EncryptedExtensions")
        r = T14Reader(msg.body)
        out = cls(t14_decode_extensions(r.vec16()))
        r.require_end()
        return out


@dataclass
class T14CertificateRequest:
    request_context: bytes = b""
    signature_algorithms: list[T14SignatureScheme] = field(default_factory=list)
    extensions: list[T14Extension] = field(default_factory=list)

    def encode(self) -> bytes:
        body = bytearray()
        t14_append_vec8(body, self.request_context)
        extensions = [T14Extension(
            T14_EXT_SIGNATURE_ALGORITHMS,
            t14_make_signature_algorithms(self.signature_algorithms),
        )]
        t14_append_vec16(body, t14_encode_extensions(extensions))
        return T14HandshakeMessage(T14_HS_CERTIFICATE_REQUEST,
                                   bytes(body)).encode()

    @classmethod
    def decode(cls, message: bytes) -> "T14CertificateRequest":
        msg = T14HandshakeMessage.decode(message)
        if msg.type != T14_HS_CERTIFICATE_REQUEST:
            raise T14Error("not a CertificateRequest")
        r = T14Reader(msg.body)
        out = cls()
        out.request_context = r.vec8()
        out.extensions = t14_decode_extensions(r.vec16())
        sig = t14_find_extension(out.extensions,
                                 T14_EXT_SIGNATURE_ALGORITHMS)
        if sig is None:
            raise T14Error("CertificateRequest: missing signature_algorithms")
        out.signature_algorithms = t14_parse_signature_algorithms(sig.data)
        r.require_end()
        return out


@dataclass
class T14CertificateVerify:
    scheme: T14SignatureScheme = T14SignatureScheme.RSA_PSS_RSAE_SHA256
    signature: bytes = b""

    def encode(self) -> bytes:
        body = bytearray()
        t14_append_u16(body, int(self.scheme))
        t14_append_vec16(body, self.signature)
        return T14HandshakeMessage(T14_HS_CERTIFICATE_VERIFY,
                                   bytes(body)).encode()

    @classmethod
    def decode(cls, message: bytes) -> "T14CertificateVerify":
        msg = T14HandshakeMessage.decode(message)
        if msg.type != T14_HS_CERTIFICATE_VERIFY:
            raise T14Error("not a CertificateVerify")
        r = T14Reader(msg.body)
        scheme = r.u16()
        if not t14_is_supported_signature_scheme(scheme):
            raise T14Error("CertificateVerify: unsupported signature scheme")
        out = cls(T14SignatureScheme(scheme), r.vec16())
        r.require_end()
        return out


@dataclass
class T14HybridClientKeyExchange:
    rsa_kem_id: int = T14_RSA_OAEP_SHA256
    ciphertext: bytes = b""

    def encode(self) -> bytes:
        body = bytearray()
        t14_append_u8(body, self.rsa_kem_id)
        t14_append_vec16(body, self.ciphertext)
        return T14HandshakeMessage(T14_HS_HYBRID_CLIENT_KEY_EXCHANGE,
                                   bytes(body)).encode()

    @classmethod
    def decode(cls, message: bytes) -> "T14HybridClientKeyExchange":
        msg = T14HandshakeMessage.decode(message)
        if msg.type != T14_HS_HYBRID_CLIENT_KEY_EXCHANGE:
            raise T14Error("not a HybridClientKeyExchange")
        r = T14Reader(msg.body)
        out = cls(r.u8(), r.vec16())
        r.require_end()
        if out.rsa_kem_id != T14_RSA_OAEP_SHA256:
            raise T14Error("HybridClientKeyExchange: unsupported RSA KEM")
        if not out.ciphertext:
            raise T14Error("HybridClientKeyExchange: empty ciphertext")
        return out


@dataclass
class T14Finished:
    verify_data: bytes = b""

    def encode(self) -> bytes:
        return T14HandshakeMessage(T14_HS_FINISHED, self.verify_data).encode()

    @classmethod
    def decode(cls, message: bytes, h: T14Hash) -> "T14Finished":
        msg = T14HandshakeMessage.decode(message)
        if msg.type != T14_HS_FINISHED:
            raise T14Error("not a Finished")
        if len(msg.body) != t14_hash_length(h):
            raise T14Error("Finished: bad verify_data length")
        return cls(msg.body)


@dataclass
class T14KeyUpdate:
    request_update: bool = False

    def encode(self) -> bytes:
        body = bytearray()
        t14_append_u8(body, 1 if self.request_update else 0)
        return T14HandshakeMessage(T14_HS_KEY_UPDATE, bytes(body)).encode()

    @classmethod
    def decode(cls, message: bytes) -> "T14KeyUpdate":
        msg = T14HandshakeMessage.decode(message)
        if msg.type != T14_HS_KEY_UPDATE:
            raise T14Error("not a KeyUpdate")
        if len(msg.body) != 1:
            raise T14Error("KeyUpdate: bad length")
        return cls(msg.body[0] != 0)


@dataclass
class T14Transcript:
    data: bytearray = field(default_factory=bytearray)

    def add(self, message: bytes) -> None:
        self.data.extend(message)

    def hash(self, h: T14Hash) -> bytes:
        return t14_digest(h, bytes(self.data))


# ---------------------------------------------------------------------------
# T14: kulcsderiválás
# ---------------------------------------------------------------------------


def t14_combine_secrets(ecdhe: bytes, rsa_secret: bytes) -> bytes:
    if len(ecdhe) > 0xFFFF or len(rsa_secret) > 0xFFFF:
        raise T14Error("combine_secrets: component too long")
    out = bytearray(b"TLS14-HYBRID")
    t14_append_u16(out, len(ecdhe))
    out.extend(ecdhe)
    t14_append_u16(out, len(rsa_secret))
    out.extend(rsa_secret)
    return bytes(out)


@dataclass
class T14HandshakeSecrets:
    handshake_secret: bytes
    client_hs_traffic: bytes
    server_hs_traffic: bytes


@dataclass
class T14ApplicationSecrets:
    client_ap_traffic: bytes
    server_ap_traffic: bytes
    exporter_master: bytes
    resumption_master: bytes


def t14_derive_handshake_secrets(suite: T14Suite, ecdhe: bytes,
                                 rsa_secret: bytes,
                                 transcript_hash: bytes) -> T14HandshakeSecrets:
    h = t14_suite_hash(suite)
    if len(transcript_hash) != t14_hash_length(h):
        raise T14Error("derive_handshake_secrets: bad transcript hash")
    zeros = b"\x00" * t14_hash_length(h)
    early_secret = t14_hkdf_extract(h, zeros, zeros)
    derived_early = t14_derive_secret(h, early_secret, b"derived",
                                      t14_digest(h, b""))
    combined = t14_combine_secrets(ecdhe, rsa_secret)
    handshake_secret = t14_hkdf_extract(h, derived_early, combined)
    return T14HandshakeSecrets(
        handshake_secret=handshake_secret,
        client_hs_traffic=t14_derive_secret(
            h, handshake_secret, b"c hs traffic", transcript_hash
        ),
        server_hs_traffic=t14_derive_secret(
            h, handshake_secret, b"s hs traffic", transcript_hash
        ),
    )


def t14_derive_application_secrets(
        suite: T14Suite, handshake_secret: bytes,
        transcript_hash: bytes) -> T14ApplicationSecrets:
    h = t14_suite_hash(suite)
    if len(transcript_hash) != t14_hash_length(h):
        raise T14Error("derive_application_secrets: bad transcript hash")
    derived_hs = t14_derive_secret(h, handshake_secret, b"derived",
                                   t14_digest(h, b""))
    zeros = b"\x00" * t14_hash_length(h)
    master_secret = t14_hkdf_extract(h, derived_hs, zeros)
    return T14ApplicationSecrets(
        client_ap_traffic=t14_derive_secret(
            h, master_secret, b"c ap traffic", transcript_hash
        ),
        server_ap_traffic=t14_derive_secret(
            h, master_secret, b"s ap traffic", transcript_hash
        ),
        exporter_master=t14_derive_secret(
            h, master_secret, b"exp master", transcript_hash
        ),
        resumption_master=t14_derive_secret(
            h, master_secret, b"res master", transcript_hash
        ),
    )


def t14_certificate_verify_input(role: str, transcript_hash: bytes) -> bytes:
    context = f"TLS 1.4, {role} CertificateVerify".encode("utf-8")
    return context + b"\x00" + transcript_hash


# ---------------------------------------------------------------------------
# T14: rekordréteg
# ---------------------------------------------------------------------------


@dataclass
class T14RecordKeys:
    secret: bytes
    key: bytes
    iv: bytes
    sequence: int = 0
    suite: T14Suite = T14Suite.AES_128_GCM_SHA256
    hash: T14Hash = T14Hash.SHA256


@dataclass
class T14Opened:
    type: int
    content: bytes


def t14_derive_record_keys(suite: T14Suite,
                           traffic_secret: bytes) -> T14RecordKeys:
    h = t14_suite_hash(suite)
    return T14RecordKeys(
        secret=traffic_secret,
        key=t14_hkdf_expand_label(h, traffic_secret, b"key", b"",
                                  t14_suite_key_length(suite)),
        iv=t14_hkdf_expand_label(h, traffic_secret, b"iv", b"", 12),
        sequence=0,
        suite=suite,
        hash=h,
    )


def t14_next_record_keys(current: T14RecordKeys) -> T14RecordKeys:
    secret = t14_next_traffic_secret(current.hash, current.secret)
    return T14RecordKeys(
        secret=secret,
        key=t14_hkdf_expand_label(current.hash, secret, b"key", b"",
                                  t14_suite_key_length(current.suite)),
        iv=t14_hkdf_expand_label(current.hash, secret, b"iv", b"", 12),
        sequence=0,
        suite=current.suite,
        hash=current.hash,
    )


def _t14_record_header(content_type: int, length: int) -> bytes:
    return bytes([content_type, 0x03, 0x03,
                  (length >> 8) & 0xFF, length & 0xFF])


class T14RecordLayer:
    def __init__(self) -> None:
        self.write_keys: T14RecordKeys | None = None
        self.read_keys: T14RecordKeys | None = None

    def install_write_keys(self, keys: T14RecordKeys) -> None:
        if len(keys.key) not in (16, 32) or len(keys.iv) != 12:
            raise T14Error("RecordLayer: invalid write key material")
        keys.sequence = 0
        self.write_keys = keys

    def install_read_keys(self, keys: T14RecordKeys) -> None:
        if len(keys.key) not in (16, 32) or len(keys.iv) != 12:
            raise T14Error("RecordLayer: invalid read key material")
        keys.sequence = 0
        self.read_keys = keys

    def update_write_keys(self) -> None:
        if self.write_keys is None:
            raise T14Error("RecordLayer: no write keys to update")
        self.write_keys = t14_next_record_keys(self.write_keys)

    def update_read_keys(self) -> None:
        if self.read_keys is None:
            raise T14Error("RecordLayer: no read keys to update")
        self.read_keys = t14_next_record_keys(self.read_keys)

    def has_write_keys(self) -> bool:
        return self.write_keys is not None

    def has_read_keys(self) -> bool:
        return self.read_keys is not None

    def seal(self, inner_type: int, content: bytes) -> bytes:
        if len(content) > T14_MAX_PLAINTEXT:
            raise T14Error("RecordLayer: plaintext fragment too large")

        if self.write_keys is None:
            return _t14_record_header(inner_type, len(content)) + content

        keys = self.write_keys
        if keys.sequence >= T14_MAX_AES_GCM_RECORDS:
            raise T14Error(
                "RecordLayer: AES-GCM key usage limit reached; KeyUpdate required"
            )
        inner = content + bytes([inner_type])
        ciphertext_len = len(inner) + 16
        if ciphertext_len > T14_MAX_CIPHERTEXT:
            raise T14Error("RecordLayer: ciphertext too large")
        header = _t14_record_header(T14_CT_APPLICATION_DATA, ciphertext_len)
        nonce = t14_make_nonce(keys.iv, keys.sequence)
        keys.sequence += 1
        ciphertext = t14_aes_gcm_seal(keys.key, nonce, header, inner)
        return header + ciphertext

    def open(self, record: bytes) -> T14Opened:
        if len(record) < 5:
            raise T14Error("RecordLayer: record too short")
        outer_type = record[0]
        if record[1] != 0x03 or record[2] != 0x03:
            raise T14Error("RecordLayer: unsupported record version")
        length = (record[3] << 8) | record[4]
        if len(record) != 5 + length:
            raise T14Error("RecordLayer: bad record length")
        if length > T14_MAX_CIPHERTEXT:
            raise T14Error("RecordLayer: record too large")

        if self.read_keys is None:
            return T14Opened(outer_type, record[5:])

        if outer_type != T14_CT_APPLICATION_DATA:
            raise T14Error("RecordLayer: expected an encrypted record")

        keys = self.read_keys
        if keys.sequence >= T14_MAX_AES_GCM_RECORDS:
            raise T14Error(
                "RecordLayer: AES-GCM key usage limit reached; KeyUpdate required"
            )
        nonce = t14_make_nonce(keys.iv, keys.sequence)
        keys.sequence += 1
        plaintext = t14_aes_gcm_open(keys.key, nonce, record[:5], record[5:])
        if not plaintext:
            raise T14Error("RecordLayer: empty inner plaintext")

        index = len(plaintext)
        while index > 0 and plaintext[index - 1] == 0:
            index -= 1
        if index == 0:
            raise T14Error("RecordLayer: missing inner content type")
        return T14Opened(plaintext[index - 1], plaintext[:index - 1])

    def write_sequence(self) -> int:
        return self.write_keys.sequence if self.write_keys else 0

    def read_sequence(self) -> int:
        return self.read_keys.sequence if self.read_keys else 0


# ---------------------------------------------------------------------------
# T14: kapcsolat és konfiguráció
# ---------------------------------------------------------------------------


class T14Role(Enum):
    CLIENT = "client"
    SERVER = "server"


@dataclass
class T14Config:
    verify_peer: bool = True
    ca_chain: list[bytes] = field(default_factory=list)
    cert_chain: list[bytes] = field(default_factory=list)
    private_key: Any = None
    server_name: str = ""
    alpn_protocols: list[str] = field(default_factory=list)
    cipher_suites: list[T14Suite] = field(
        default_factory=lambda: [T14Suite.AES_128_GCM_SHA256,
                                 T14Suite.AES_256_GCM_SHA384]
    )
    request_client_certificate: bool = False
    require_client_certificate: bool = False


def t14_config_from_files(*, ca_file: str = "", cert_file: str = "",
                          key_file: str = "", server_name: str = "",
                          alpn_protocols: list[str] | None = None,
                          cipher_suites: list[T14Suite] | None = None,
                          verify_peer: bool = True,
                          request_client_certificate: bool = False,
                          require_client_certificate: bool = False) -> T14Config:
    ca_chain = t14_load_certificate_chain_der(ca_file) if ca_file else []
    cert_chain = t14_load_certificate_chain_der(cert_file) if cert_file else []
    private_key = t14_load_private_key(key_file) if key_file else None
    return T14Config(
        verify_peer=verify_peer,
        ca_chain=ca_chain,
        cert_chain=cert_chain,
        private_key=private_key,
        server_name=server_name,
        alpn_protocols=list(alpn_protocols or []),
        cipher_suites=list(cipher_suites or [T14Suite.AES_128_GCM_SHA256,
                                             T14Suite.AES_256_GCM_SHA384]),
        request_client_certificate=request_client_certificate,
        require_client_certificate=require_client_certificate,
    )


class T14Connection:
    def __init__(self, sock: socket.socket, role: T14Role,
                 config: T14Config):
        self.sock = sock
        self.role = role
        self.config = config
        self.records = T14RecordLayer()
        self.transcript = T14Transcript()
        self.hash_ = T14Hash.SHA256
        self.suite_ = T14Suite.AES_128_GCM_SHA256
        self.client_random_ = b""
        self.server_random_ = b""
        self.session_id_ = b""
        self.ecdh_public_ = b""
        self.handshake_secret_ = b""
        self.client_hs_secret_ = b""
        self.server_hs_secret_ = b""
        self.sni_ = ""
        self.alpn_ = ""
        self.handshake_buffer_ = bytearray()
        self.app_buffer_ = bytearray()
        self.handshake_complete_ = False
        self.closed_ = False
        self.peer_closed_ = False
        self.peer_alert_ = False

    # -- I/O -------------------------------------------------------------
    def write_all(self, data: bytes) -> None:
        try:
            self.sock.sendall(data)
        except OSError as exc:
            raise T14Error(f"send failed: {exc}") from exc

    def recv_exact(self, length: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < length:
            try:
                chunk = self.sock.recv(length - len(chunks))
            except OSError as exc:
                raise T14Error(f"recv failed: {exc}") from exc
            if not chunk:
                if not chunks:
                    raise T14ConnectionClosed()
                raise T14Alert(T14_ALERT_DECRYPT_ERROR,
                               "truncated record")
            chunks.extend(chunk)
        return bytes(chunks)

    def send_record(self, content_type: int, content: bytes) -> None:
        self.write_all(self.records.seal(content_type, content))

    def recv_record(self) -> T14Opened:
        header = self.recv_exact(5)
        length = (header[3] << 8) | header[4]
        if length > T14_MAX_CIPHERTEXT:
            raise T14Alert(T14_ALERT_RECORD_OVERFLOW, "record too large")
        body = self.recv_exact(length)
        try:
            return self.records.open(header + body)
        except T14Alert:
            raise
        except T14Error as exc:
            raise T14Alert(T14_ALERT_BAD_RECORD_MAC, str(exc)) from exc

    def send_handshake_bytes(self, encoded: bytes) -> None:
        offset = 0
        while offset < len(encoded):
            chunk = encoded[offset:offset + T14_MAX_PLAINTEXT]
            self.send_record(T14_CT_HANDSHAKE, chunk)
            offset += len(chunk)

    def send_handshake(self, message: T14HandshakeMessage) -> None:
        self.send_handshake_bytes(message.encode())

    def recv_handshake(self) -> T14HandshakeMessage:
        while True:
            if len(self.handshake_buffer_) >= 4:
                length = ((self.handshake_buffer_[1] << 16)
                          | (self.handshake_buffer_[2] << 8)
                          | self.handshake_buffer_[3])
                if length > 0xFFFFFF:
                    raise T14Alert(T14_ALERT_DECODE_ERROR,
                                   "handshake message too large")
                if len(self.handshake_buffer_) >= 4 + length:
                    encoded = bytes(self.handshake_buffer_[:4 + length])
                    del self.handshake_buffer_[:4 + length]
                    return T14HandshakeMessage.decode(encoded)

            record = self.recv_record()
            if record.type == T14_CT_HANDSHAKE:
                if not record.content:
                    raise T14Alert(T14_ALERT_DECODE_ERROR,
                                   "empty handshake record")
                if (len(self.handshake_buffer_) + len(record.content)
                        > T14_MAX_HANDSHAKE_BUFFER):
                    raise T14Alert(T14_ALERT_DECODE_ERROR,
                                   "handshake buffer too large")
                self.handshake_buffer_.extend(record.content)
            elif record.type == T14_CT_ALERT:
                self.handle_alert(record.content)
            elif record.type == T14_CT_CHANGE_CIPHER_SPEC:
                continue
            elif record.type == T14_CT_APPLICATION_DATA:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "application data during handshake")
            else:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "unexpected record type")

    def send_alert(self, level: int, description: int) -> None:
        self.send_record(T14_CT_ALERT, bytes([level, description]))

    def handle_alert(self, content: bytes) -> None:
        self.peer_alert_ = True
        if len(content) != 2:
            raise T14Alert(T14_ALERT_DECODE_ERROR, "malformed alert")
        level, description = content[0], content[1]
        if level not in (T14_ALERT_WARNING, T14_ALERT_FATAL):
            raise T14Alert(T14_ALERT_DECODE_ERROR, "invalid alert level")
        if description == T14_ALERT_CLOSE_NOTIFY:
            self.peer_closed_ = True
            if not self.handshake_complete_:
                raise T14ConnectionClosed()
            return
        raise T14Alert(description, f"peer sent alert {description}")

    def install_handshake_keys(self, secrets: T14HandshakeSecrets,
                               as_client: bool) -> None:
        self.client_hs_secret_ = secrets.client_hs_traffic
        self.server_hs_secret_ = secrets.server_hs_traffic
        if as_client:
            self.records.install_write_keys(
                t14_derive_record_keys(self.suite_, self.client_hs_secret_)
            )
            self.records.install_read_keys(
                t14_derive_record_keys(self.suite_, self.server_hs_secret_)
            )
        else:
            self.records.install_write_keys(
                t14_derive_record_keys(self.suite_, self.server_hs_secret_)
            )
            self.records.install_read_keys(
                t14_derive_record_keys(self.suite_, self.client_hs_secret_)
            )

    def install_application_keys(self, secrets: T14ApplicationSecrets,
                                 as_client: bool) -> None:
        if as_client:
            self.records.install_write_keys(
                t14_derive_record_keys(self.suite_, secrets.client_ap_traffic)
            )
            self.records.install_read_keys(
                t14_derive_record_keys(self.suite_, secrets.server_ap_traffic)
            )
        else:
            self.records.install_write_keys(
                t14_derive_record_keys(self.suite_, secrets.server_ap_traffic)
            )
            self.records.install_read_keys(
                t14_derive_record_keys(self.suite_, secrets.client_ap_traffic)
            )

    def process_post_handshake_messages(self) -> None:
        while len(self.handshake_buffer_) >= 4:
            length = ((self.handshake_buffer_[1] << 16)
                      | (self.handshake_buffer_[2] << 8)
                      | self.handshake_buffer_[3])
            if length > 0xFFFFFF:
                raise T14Alert(T14_ALERT_DECODE_ERROR,
                               "post-handshake message too large")
            if len(self.handshake_buffer_) < 4 + length:
                return
            encoded = bytes(self.handshake_buffer_[:4 + length])
            del self.handshake_buffer_[:4 + length]
            message = T14HandshakeMessage.decode(encoded)
            if message.type == T14_HS_KEY_UPDATE:
                update = T14KeyUpdate.decode(encoded)
                self.records.update_read_keys()
                if update.request_update:
                    self.send_handshake_bytes(T14KeyUpdate(False).encode())
                    self.records.update_write_keys()
            elif message.type == T14_HS_NEW_SESSION_TICKET:
                pass
            else:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "unexpected post-handshake message")

    # -- application data ------------------------------------------------
    def write_app(self, data: bytes) -> int:
        if not self.handshake_complete_:
            raise T14Error("write_app before handshake")
        if self.closed_:
            raise T14Error("write_app on a closed connection")
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + T14_MAX_PLAINTEXT]
            self.send_record(T14_CT_APPLICATION_DATA, chunk)
            offset += len(chunk)
        return offset

    def read_app(self, length: int) -> bytes:
        if not self.handshake_complete_:
            raise T14Error("read_app before handshake")
        if self.closed_:
            raise T14Error("read_app on a closed connection")
        if length == 0:
            return b""

        while not self.app_buffer_:
            if self.peer_closed_:
                return b""
            try:
                record = self.recv_record()
            except T14ConnectionClosed:
                self.peer_closed_ = True
                return b""

            if record.type == T14_CT_APPLICATION_DATA:
                self.app_buffer_ = bytearray(record.content)
            elif record.type == T14_CT_HANDSHAKE:
                if not record.content:
                    raise T14Alert(T14_ALERT_DECODE_ERROR,
                                   "empty handshake record")
                if (len(self.handshake_buffer_) + len(record.content)
                        > T14_MAX_HANDSHAKE_BUFFER):
                    raise T14Alert(T14_ALERT_DECODE_ERROR,
                                   "handshake buffer too large")
                self.handshake_buffer_.extend(record.content)
                self.process_post_handshake_messages()
            elif record.type == T14_CT_ALERT:
                self.handle_alert(record.content)
                if self.peer_closed_:
                    return b""
            elif record.type == T14_CT_CHANGE_CIPHER_SPEC:
                continue
            else:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "unexpected record type")

        count = min(length, len(self.app_buffer_))
        out = bytes(self.app_buffer_[:count])
        del self.app_buffer_[:count]
        return out

    def key_update(self, request_update: bool = False) -> None:
        if not self.handshake_complete_:
            raise T14Error("key_update before handshake")
        if self.closed_:
            raise T14Error("key_update on a closed connection")
        self.send_handshake_bytes(T14KeyUpdate(request_update).encode())
        self.records.update_write_keys()

    def close(self) -> None:
        if self.closed_:
            return
        if self.handshake_complete_ and not self.peer_closed_ and not self.peer_alert_:
            try:
                self.send_alert(T14_ALERT_WARNING, T14_ALERT_CLOSE_NOTIFY)
            except Exception:
                pass
        self.close_socket()

    def close_socket(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
        self.closed_ = True

    @property
    def alpn(self) -> str:
        return self.alpn_

    @property
    def sni(self) -> str:
        return self.sni_

    @property
    def cipher_suite(self) -> T14Suite:
        return self.suite_

    @property
    def handshake_complete(self) -> bool:
        return self.handshake_complete_

    # -- hibakezelés -----------------------------------------------------
    def _handshake_failed(self, prefix: str, exc: Exception) -> Exception:
        if isinstance(exc, T14ConnectionClosed):
            self.close_socket()
            return exc
        if not self.closed_ and not self.peer_alert_:
            try:
                if isinstance(exc, T14Alert):
                    self.send_alert(T14_ALERT_FATAL, exc.description)
                else:
                    self.send_alert(T14_ALERT_FATAL,
                                    T14_ALERT_HANDSHAKE_FAILURE)
            except Exception:
                pass
        self.close_socket()
        if isinstance(exc, T14Alert):
            return exc
        if isinstance(exc, T14ConnectionClosed):
            return exc
        return T14Error(f"{prefix} handshake failed: {exc}")


def _t14_contains(values: list[Any], value: Any) -> bool:
    return value in values


class T14Client(T14Connection):
    def __init__(self, sock: socket.socket, config: T14Config):
        super().__init__(sock, T14Role.CLIENT, config)

    def handshake(self) -> None:
        if self.handshake_complete_:
            raise T14Error("client handshake already complete")
        try:
            if self.config.verify_peer and not self.config.ca_chain:
                raise T14Error(
                    "client: ca_file is required when verify_peer is enabled"
                )
            if self.config.verify_peer and not self.config.server_name:
                raise T14Error(
                    "client: server_name is required when verify_peer is enabled"
                )
            self.sni_ = self.config.server_name

            ecdhe = t14_x25519_generate()
            self.ecdh_public_ = t14_x25519_public(ecdhe)
            self.client_random_ = t14_random_bytes(32)
            self.session_id_ = t14_random_bytes(32)

            ch = T14ClientHello(
                random=self.client_random_,
                session_id=self.session_id_,
                cipher_suites=list(self.config.cipher_suites),
            )
            ch.extensions = [
                T14Extension(T14_EXT_SUPPORTED_VERSIONS,
                             t14_make_supported_versions_client()),
                T14Extension(T14_EXT_KEY_SHARE,
                             t14_make_key_share_client(T14_GROUP_X25519,
                                                       self.ecdh_public_)),
                T14Extension(T14_EXT_SUPPORTED_GROUPS,
                             t14_make_supported_groups([T14_GROUP_X25519])),
                T14Extension(T14_EXT_SIGNATURE_ALGORITHMS,
                             t14_make_signature_algorithms(
                                 T14_DEFAULT_SIGNATURE_SCHEMES)),
                T14Extension(T14_EXT_HYBRID_RSA_KEM,
                             t14_make_hybrid_rsa_kem_offer()),
            ]
            if self.config.server_name:
                ch.extensions.append(T14Extension(
                    T14_EXT_SERVER_NAME,
                    t14_make_server_name(self.config.server_name),
                ))
            if self.config.alpn_protocols:
                ch.extensions.append(T14Extension(
                    T14_EXT_ALPN,
                    t14_make_alpn(self.config.alpn_protocols),
                ))

            ch_bytes = ch.encode()
            self.send_handshake_bytes(ch_bytes)
            self.transcript.add(ch_bytes)

            sh_msg = self.recv_handshake()
            if sh_msg.type != T14_HS_SERVER_HELLO:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "expected ServerHello")
            sh = T14ServerHello.decode(sh_msg.encode())
            self.transcript.add(sh_msg.encode())

            if sh.session_id_echo != self.session_id_:
                raise T14Alert(T14_ALERT_ILLEGAL_PARAMETER,
                               "session id echo mismatch")
            if sh.cipher_suite not in ch.cipher_suites:
                raise T14Alert(T14_ALERT_ILLEGAL_PARAMETER,
                               "server selected an unoffered suite")
            self.suite_ = sh.cipher_suite
            self.hash_ = t14_suite_hash(self.suite_)
            self.server_random_ = sh.random

            sv = t14_find_extension(sh.extensions, T14_EXT_SUPPORTED_VERSIONS)
            if sv is None:
                raise T14Alert(T14_ALERT_MISSING_EXTENSION,
                               "missing supported_versions")
            sv_reader = T14Reader(sv.data)
            if sv_reader.u16() != T14_VERSION:
                raise T14Alert(T14_ALERT_PROTOCOL_VERSION,
                               "server selected an unsupported version")
            sv_reader.require_end()

            ks = t14_find_extension(sh.extensions, T14_EXT_KEY_SHARE)
            if ks is None:
                raise T14Alert(T14_ALERT_MISSING_EXTENSION, "missing key_share")
            server_share = t14_parse_key_share_single(ks.data)
            if (server_share.group != T14_GROUP_X25519
                    or len(server_share.key_exchange) != 32):
                raise T14Alert(T14_ALERT_ILLEGAL_PARAMETER,
                               "bad server key share")

            cert_msg = self.recv_handshake()
            if cert_msg.type != T14_HS_CERTIFICATE:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "expected Certificate")
            chain = T14CertificateChain.decode(cert_msg.encode())
            self.transcript.add(cert_msg.encode())
            if not chain.certificates:
                raise T14Alert(T14_ALERT_BAD_CERTIFICATE,
                               "server sent an empty certificate")
            if chain.request_context:
                raise T14Alert(T14_ALERT_ILLEGAL_PARAMETER,
                               "server certificate context must be empty")

            if self.config.verify_peer:
                verifier = T14CertificateVerifier(self.config.ca_chain)
                try:
                    verifier.verify_server(chain, self.config.server_name)
                except Exception as exc:
                    raise T14Alert(T14_ALERT_BAD_CERTIFICATE, str(exc)) from exc
                server_key = verifier.leaf_public_key(chain)
            else:
                server_key = t14_certificate_leaf_public_key(chain)
            if not isinstance(server_key, rsa.RSAPublicKey):
                raise T14Alert(T14_ALERT_UNSUPPORTED_CERTIFICATE,
                               "server certificate must contain an RSA key")
            if server_key.key_size < 2048:
                raise T14Alert(T14_ALERT_UNSUPPORTED_CERTIFICATE,
                               "server RSA key is smaller than 2048 bits")

            cv_msg = self.recv_handshake()
            if cv_msg.type != T14_HS_CERTIFICATE_VERIFY:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "expected CertificateVerify")
            cv = T14CertificateVerify.decode(cv_msg.encode())
            if cv.scheme not in T14_DEFAULT_SIGNATURE_SCHEMES:
                raise T14Alert(T14_ALERT_ILLEGAL_PARAMETER,
                               "server used an unoffered signature scheme")
            cv_input = t14_certificate_verify_input(
                "server", self.transcript.hash(self.hash_)
            )
            if not t14_verify_with_scheme(server_key, cv.scheme, cv_input,
                                          cv.signature):
                raise T14Alert(T14_ALERT_DECRYPT_ERROR,
                               "server CertificateVerify failed")
            self.transcript.add(cv_msg.encode())

            cert_request: T14CertificateRequest | None = None
            next_msg = self.recv_handshake()
            if next_msg.type == T14_HS_CERTIFICATE_REQUEST:
                cert_request = T14CertificateRequest.decode(next_msg.encode())
                self.transcript.add(next_msg.encode())
                next_msg = self.recv_handshake()
            if (next_msg.type != T14_HS_SERVER_HELLO_DONE
                    or next_msg.body):
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "expected ServerHelloDone")
            self.transcript.add(next_msg.encode())

            th_hs = self.transcript.hash(self.hash_)
            rsa_secret = t14_random_bytes(32)
            rsa_ciphertext = t14_rsa_oaep_encrypt(server_key, rsa_secret)
            cke = T14HybridClientKeyExchange(ciphertext=rsa_ciphertext)
            cke_bytes = cke.encode()
            self.send_handshake_bytes(cke_bytes)
            self.transcript.add(cke_bytes)

            ecdhe_shared = t14_x25519_derive(
                ecdhe, server_share.key_exchange
            )
            hs = t14_derive_handshake_secrets(
                self.suite_, ecdhe_shared, rsa_secret, th_hs
            )
            self.install_handshake_keys(hs, True)

            if cert_request is not None and cert_request.signature_algorithms:
                client_chain = T14CertificateChain(
                    request_context=cert_request.request_context
                )
                if self.config.cert_chain and self.config.private_key is not None:
                    client_chain.certificates = list(self.config.cert_chain)
                client_cert_bytes = client_chain.encode()
                self.send_handshake_bytes(client_cert_bytes)
                self.transcript.add(client_cert_bytes)

                if client_chain.certificates:
                    if not t14_certificate_matches_private_key(
                            client_chain, self.config.private_key):
                        raise T14Alert(
                            T14_ALERT_BAD_CERTIFICATE,
                            "client certificate does not match private key",
                        )
                    scheme = t14_choose_signature_scheme(
                        self.config.private_key,
                        cert_request.signature_algorithms,
                        self.hash_,
                    )
                    client_cv = T14CertificateVerify(
                        scheme,
                        t14_sign_with_scheme(
                            self.config.private_key, scheme,
                            t14_certificate_verify_input(
                                "client", self.transcript.hash(self.hash_)
                            ),
                        ),
                    )
                    client_cv_bytes = client_cv.encode()
                    self.send_handshake_bytes(client_cv_bytes)
                    self.transcript.add(client_cv_bytes)

            client_finished = t14_finished_verify_data(
                self.hash_, self.client_hs_secret_,
                self.transcript.hash(self.hash_),
            )
            client_finished_bytes = T14Finished(client_finished).encode()
            self.send_handshake_bytes(client_finished_bytes)
            self.transcript.add(client_finished_bytes)

            ee_msg = self.recv_handshake()
            if ee_msg.type != T14_HS_ENCRYPTED_EXTENSIONS:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "expected EncryptedExtensions")
            ee = T14EncryptedExtensions.decode(ee_msg.encode())
            self.transcript.add(ee_msg.encode())

            alpn_ext = t14_find_extension(ee.extensions, T14_EXT_ALPN)
            if alpn_ext is not None:
                selected = t14_parse_alpn(alpn_ext.data)
                if (len(selected) != 1
                        or selected[0] not in self.config.alpn_protocols):
                    raise T14Alert(T14_ALERT_ILLEGAL_PARAMETER,
                                   "server selected an unoffered ALPN")
                self.alpn_ = selected[0]
            elif self.config.alpn_protocols:
                raise T14Alert(T14_ALERT_NO_APPLICATION_PROTOCOL,
                               "server did not select an ALPN protocol")

            sf_msg = self.recv_handshake()
            if sf_msg.type != T14_HS_FINISHED:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "expected server Finished")
            sf = T14Finished.decode(sf_msg.encode(), self.hash_)
            expected_sf = t14_finished_verify_data(
                self.hash_, self.server_hs_secret_,
                self.transcript.hash(self.hash_),
            )
            if not hmac.compare_digest(sf.verify_data, expected_sf):
                raise T14Alert(T14_ALERT_DECRYPT_ERROR,
                               "server Finished mismatch")
            self.transcript.add(sf_msg.encode())

            app = t14_derive_application_secrets(
                self.suite_, hs.handshake_secret,
                self.transcript.hash(self.hash_),
            )
            self.install_application_keys(app, True)
            self.handshake_complete_ = True
        except (T14Alert, T14ConnectionClosed) as exc:
            raise self._handshake_failed("client", exc)
        except Exception as exc:
            raise self._handshake_failed("client", exc)


class T14Server(T14Connection):
    def __init__(self, sock: socket.socket, config: T14Config):
        super().__init__(sock, T14Role.SERVER, config)

    def handshake(self) -> None:
        if self.handshake_complete_:
            raise T14Error("server handshake already complete")
        try:
            if not self.config.cert_chain or self.config.private_key is None:
                raise T14Error("server: cert_file and key_file are required")
            if (self.config.require_client_certificate
                    and not self.config.request_client_certificate):
                raise T14Error(
                    "server: require_client_certificate needs "
                    "request_client_certificate"
                )
            if (self.config.request_client_certificate
                    and self.config.verify_peer
                    and not self.config.ca_chain):
                raise T14Error(
                    "server: ca_file is required to verify client certificates"
                )

            ch_msg = self.recv_handshake()
            if ch_msg.type != T14_HS_CLIENT_HELLO:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "expected ClientHello")
            ch = T14ClientHello.decode(ch_msg.encode())
            self.transcript.add(ch_msg.encode())
            self.client_random_ = ch.random
            self.session_id_ = ch.session_id

            sv = t14_find_extension(ch.extensions,
                                    T14_EXT_SUPPORTED_VERSIONS)
            if sv is None:
                raise T14Alert(T14_ALERT_MISSING_EXTENSION,
                               "missing supported_versions")
            if T14_VERSION not in t14_parse_supported_versions_client(sv.data):
                raise T14Alert(T14_ALERT_PROTOCOL_VERSION,
                               "client does not support TLS 1.4")

            hybrid = t14_find_extension(ch.extensions, T14_EXT_HYBRID_RSA_KEM)
            if hybrid is None:
                raise T14Alert(T14_ALERT_MISSING_EXTENSION,
                               "client does not offer hybrid_rsa_kem")
            hr = T14Reader(hybrid.data)
            if hr.u16() != 1 or hr.u8() != 1:
                raise T14Alert(T14_ALERT_ILLEGAL_PARAMETER,
                               "unsupported hybrid_rsa_kem parameters")
            hr.require_end()

            ks = t14_find_extension(ch.extensions, T14_EXT_KEY_SHARE)
            if ks is None:
                raise T14Alert(T14_ALERT_MISSING_EXTENSION,
                               "missing key_share")
            client_share = None
            for share in t14_parse_key_share_list(ks.data):
                if share.group == T14_GROUP_X25519:
                    if len(share.key_exchange) != 32:
                        raise T14Alert(T14_ALERT_ILLEGAL_PARAMETER,
                                       "bad X25519 key share length")
                    client_share = share
                    break
            if client_share is None:
                raise T14Alert(T14_ALERT_HANDSHAKE_FAILURE,
                               "no X25519 key share")

            sig = t14_find_extension(ch.extensions,
                                     T14_EXT_SIGNATURE_ALGORITHMS)
            if sig is None:
                raise T14Alert(T14_ALERT_MISSING_EXTENSION,
                               "missing signature_algorithms")
            client_sig_algs = t14_parse_signature_algorithms(sig.data)
            if not client_sig_algs:
                raise T14Alert(T14_ALERT_HANDSHAKE_FAILURE,
                               "no supported signature algorithms")

            client_alpn: list[str] = []
            alpn_ext = t14_find_extension(ch.extensions, T14_EXT_ALPN)
            if alpn_ext is not None:
                client_alpn = t14_parse_alpn(alpn_ext.data)
            sni_ext = t14_find_extension(ch.extensions, T14_EXT_SERVER_NAME)
            if sni_ext is not None:
                self.sni_ = t14_parse_server_name(sni_ext.data)

            selected = [s for s in ch.cipher_suites
                        if s in self.config.cipher_suites]
            if not selected:
                raise T14Alert(T14_ALERT_HANDSHAKE_FAILURE,
                               "no common cipher suite")
            self.suite_ = selected[0]
            self.hash_ = t14_suite_hash(self.suite_)

            server_ecdhe = t14_x25519_generate()
            self.ecdh_public_ = t14_x25519_public(server_ecdhe)
            self.server_random_ = t14_random_bytes(32)

            sh = T14ServerHello(
                random=self.server_random_,
                session_id_echo=ch.session_id,
                cipher_suite=self.suite_,
            )
            sh.extensions = [
                T14Extension(T14_EXT_SUPPORTED_VERSIONS,
                             t14_make_supported_versions_server()),
                T14Extension(T14_EXT_KEY_SHARE,
                             t14_make_key_share_server(T14_GROUP_X25519,
                                                       self.ecdh_public_)),
            ]
            sh_bytes = sh.encode()
            self.send_handshake_bytes(sh_bytes)
            self.transcript.add(sh_bytes)

            server_chain = T14CertificateChain(
                certificates=list(self.config.cert_chain)
            )
            if not server_chain.certificates:
                raise T14Error("server: certificate chain is empty")
            server_key = self.config.private_key
            if not t14_certificate_matches_private_key(server_chain,
                                                        server_key):
                raise T14Error("server: certificate does not match private key")
            if (not isinstance(server_key, rsa.RSAPrivateKey)
                    or server_key.key_size < 2048):
                raise T14Error(
                    "server: an RSA key of at least 2048 bits is required"
                )

            server_cert_bytes = server_chain.encode()
            self.send_handshake_bytes(server_cert_bytes)
            self.transcript.add(server_cert_bytes)

            server_scheme = t14_choose_signature_scheme(
                server_key, client_sig_algs, self.hash_
            )
            server_cv = T14CertificateVerify(
                server_scheme,
                t14_sign_with_scheme(
                    server_key, server_scheme,
                    t14_certificate_verify_input(
                        "server", self.transcript.hash(self.hash_)
                    ),
                ),
            )
            server_cv_bytes = server_cv.encode()
            self.send_handshake_bytes(server_cv_bytes)
            self.transcript.add(server_cv_bytes)

            if self.config.request_client_certificate:
                cr = T14CertificateRequest(
                    signature_algorithms=list(T14_DEFAULT_SIGNATURE_SCHEMES)
                )
                cr_bytes = cr.encode()
                self.send_handshake_bytes(cr_bytes)
                self.transcript.add(cr_bytes)

            shd_bytes = T14HandshakeMessage(
                T14_HS_SERVER_HELLO_DONE, b""
            ).encode()
            self.send_handshake_bytes(shd_bytes)
            self.transcript.add(shd_bytes)

            th_hs = self.transcript.hash(self.hash_)

            cke_msg = self.recv_handshake()
            if cke_msg.type != T14_HS_HYBRID_CLIENT_KEY_EXCHANGE:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "expected HybridClientKeyExchange")
            cke = T14HybridClientKeyExchange.decode(cke_msg.encode())
            self.transcript.add(cke_msg.encode())

            try:
                rsa_secret = t14_rsa_oaep_decrypt(
                    server_key, cke.ciphertext
                )
                if len(rsa_secret) != 32:
                    raise T14Error("RSA secret has the wrong length")
            except Exception:
                # Implicit rejection: a hamis titokkal folytatjuk, és a kliens
                # Finished ellenőrzése fog elbukni. Nincs azonnali RSA oracle.
                rsa_secret = t14_digest(
                    T14Hash.SHA256, b"TLS14-REJECT" + cke.ciphertext
                )

            ecdhe_shared = t14_x25519_derive(
                server_ecdhe, client_share.key_exchange
            )
            hs = t14_derive_handshake_secrets(
                self.suite_, ecdhe_shared, rsa_secret, th_hs
            )
            self.install_handshake_keys(hs, False)

            if self.config.request_client_certificate:
                client_cert_msg = self.recv_handshake()
                if client_cert_msg.type != T14_HS_CERTIFICATE:
                    raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                                   "expected client Certificate")
                client_chain = T14CertificateChain.decode(
                    client_cert_msg.encode()
                )
                self.transcript.add(client_cert_msg.encode())
                if client_chain.request_context:
                    raise T14Alert(
                        T14_ALERT_ILLEGAL_PARAMETER,
                        "client certificate request context mismatch",
                    )

                if not client_chain.certificates:
                    if self.config.require_client_certificate:
                        raise T14Alert(
                            T14_ALERT_CERTIFICATE_REQUIRED,
                            "server requires a client certificate",
                        )
                else:
                    if self.config.verify_peer:
                        verifier = T14CertificateVerifier(
                            self.config.ca_chain
                        )
                        try:
                            verifier.verify_client(client_chain)
                        except Exception as exc:
                            raise T14Alert(T14_ALERT_BAD_CERTIFICATE,
                                           str(exc)) from exc
                        client_key = verifier.leaf_public_key(client_chain)
                    else:
                        client_key = t14_certificate_leaf_public_key(
                            client_chain
                        )

                    client_cv_msg = self.recv_handshake()
                    if client_cv_msg.type != T14_HS_CERTIFICATE_VERIFY:
                        raise T14Alert(
                            T14_ALERT_UNEXPECTED_MESSAGE,
                            "expected client CertificateVerify",
                        )
                    client_cv = T14CertificateVerify.decode(
                        client_cv_msg.encode()
                    )
                    if client_cv.scheme not in client_sig_algs:
                        raise T14Alert(
                            T14_ALERT_ILLEGAL_PARAMETER,
                            "client used an unoffered signature scheme",
                        )
                    cv_input = t14_certificate_verify_input(
                        "client", self.transcript.hash(self.hash_)
                    )
                    if not t14_verify_with_scheme(
                            client_key, client_cv.scheme, cv_input,
                            client_cv.signature):
                        raise T14Alert(
                            T14_ALERT_DECRYPT_ERROR,
                            "client CertificateVerify failed",
                        )
                    self.transcript.add(client_cv_msg.encode())

            cf_msg = self.recv_handshake()
            if cf_msg.type != T14_HS_FINISHED:
                raise T14Alert(T14_ALERT_UNEXPECTED_MESSAGE,
                               "expected client Finished")
            cf = T14Finished.decode(cf_msg.encode(), self.hash_)
            expected_cf = t14_finished_verify_data(
                self.hash_, self.client_hs_secret_,
                self.transcript.hash(self.hash_),
            )
            if not hmac.compare_digest(cf.verify_data, expected_cf):
                raise T14Alert(T14_ALERT_DECRYPT_ERROR,
                               "client Finished mismatch")
            self.transcript.add(cf_msg.encode())

            ee = T14EncryptedExtensions()
            if client_alpn:
                chosen = ""
                for protocol in self.config.alpn_protocols:
                    if protocol in client_alpn:
                        chosen = protocol
                        break
                if not chosen:
                    raise T14Alert(
                        T14_ALERT_NO_APPLICATION_PROTOCOL,
                        "no common ALPN protocol",
                    )
                self.alpn_ = chosen
                ee.extensions.append(T14Extension(
                    T14_EXT_ALPN, t14_make_alpn([chosen])
                ))
            ee_bytes = ee.encode()
            self.send_handshake_bytes(ee_bytes)
            self.transcript.add(ee_bytes)

            server_finished = t14_finished_verify_data(
                self.hash_, self.server_hs_secret_,
                self.transcript.hash(self.hash_),
            )
            server_finished_bytes = T14Finished(server_finished).encode()
            self.send_handshake_bytes(server_finished_bytes)
            self.transcript.add(server_finished_bytes)

            app = t14_derive_application_secrets(
                self.suite_, hs.handshake_secret,
                self.transcript.hash(self.hash_),
            )
            self.install_application_keys(app, False)
            self.handshake_complete_ = True
        except (T14Alert, T14ConnectionClosed) as exc:
            raise self._handshake_failed("server", exc)
        except Exception as exc:
            raise self._handshake_failed("server", exc)


# ---------------------------------------------------------------------------
# T14: teszt-tanúsítványok generálása (a tools/gen_certs.sh Python megfelelője)
# ---------------------------------------------------------------------------


@dataclass
class T14GeneratedCerts:
    ca_key: Any
    ca_cert: Any
    ca_der: bytes
    server_key: Any
    server_cert: Any
    server_der: bytes
    server_chain: list[bytes]
    client_key: Any
    client_cert: Any
    client_der: bytes
    client_chain: list[bytes]
    client_ec_key: Any
    client_ec_cert: Any
    client_ec_der: bytes
    client_ec_chain: list[bytes]
    bad_server_cert: Any
    bad_server_der: bytes
    bad_server_chain: list[bytes]


def _t14_name(cn: str) -> Any:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _t14_cert_base(subject: str, issuer: str, public_key: Any,
                   serial: int | None = None):
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_t14_name(subject))
        .issuer_name(_t14_name(issuer))
        .public_key(public_key)
        .serial_number(serial if serial is not None
                       else x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=3650))
    )


def t14_generate_test_certs() -> T14GeneratedCerts:
    _require_crypto()

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = (
        _t14_cert_base("TLS14 Test CA", "TLS14 Test CA", ca_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_der = ca_cert.public_bytes(serialization.Encoding.DER)

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = (
        _t14_cert_base("localhost", "TLS14 Test CA", server_key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    server_der = server_cert.public_bytes(serialization.Encoding.DER)

    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_cert = (
        _t14_cert_base("client.test", "TLS14 Test CA",
                       client_key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("client.test"),
        ]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    client_der = client_cert.public_bytes(serialization.Encoding.DER)

    client_ec_key = ec.generate_private_key(ec.SECP256R1())
    client_ec_cert = (
        _t14_cert_base("client-ec.test", "TLS14 Test CA",
                       client_ec_key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("client-ec.test"),
        ]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    client_ec_der = client_ec_cert.public_bytes(serialization.Encoding.DER)

    # Szándékosan hiányos: nincs keyUsage, EKU, SAN.
    bad_server_cert = (
        _t14_cert_base("localhost", "TLS14 Test CA",
                       server_key.public_key())
        .sign(ca_key, hashes.SHA256())
    )
    bad_server_der = bad_server_cert.public_bytes(serialization.Encoding.DER)

    return T14GeneratedCerts(
        ca_key=ca_key,
        ca_cert=ca_cert,
        ca_der=ca_der,
        server_key=server_key,
        server_cert=server_cert,
        server_der=server_der,
        server_chain=[server_der, ca_der],
        client_key=client_key,
        client_cert=client_cert,
        client_der=client_der,
        client_chain=[client_der, ca_der],
        client_ec_key=client_ec_key,
        client_ec_cert=client_ec_cert,
        client_ec_der=client_ec_der,
        client_ec_chain=[client_ec_der, ca_der],
        bad_server_cert=bad_server_cert,
        bad_server_der=bad_server_der,
        bad_server_chain=[bad_server_der, ca_der],
    )


def _t14_write_pem(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def t14_write_cert_files(directory: str) -> None:
    _require_crypto()
    certs = t14_generate_test_certs()
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)

    def pem_cert(cert: Any) -> bytes:
        return cert.public_bytes(serialization.Encoding.PEM)

    def pem_key(key: Any) -> bytes:
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

    _t14_write_pem(target / "ca.crt", pem_cert(certs.ca_cert))
    _t14_write_pem(target / "ca.key", pem_key(certs.ca_key))
    _t14_write_pem(target / "server.crt", pem_cert(certs.server_cert))
    _t14_write_pem(target / "server.key", pem_key(certs.server_key))
    _t14_write_pem(target / "server-chain.crt",
                   pem_cert(certs.server_cert) + pem_cert(certs.ca_cert))
    _t14_write_pem(target / "client.crt", pem_cert(certs.client_cert))
    _t14_write_pem(target / "client.key", pem_key(certs.client_key))
    _t14_write_pem(target / "client-chain.crt",
                   pem_cert(certs.client_cert) + pem_cert(certs.ca_cert))
    _t14_write_pem(target / "client-ec.crt", pem_cert(certs.client_ec_cert))
    _t14_write_pem(target / "client-ec.key", pem_key(certs.client_ec_key))
    _t14_write_pem(target / "client-ec-chain.crt",
                   pem_cert(certs.client_ec_cert) + pem_cert(certs.ca_cert))
    _t14_write_pem(target / "bad-server.crt", pem_cert(certs.bad_server_cert))
    _t14_write_pem(target / "bad-server-chain.crt",
                   pem_cert(certs.bad_server_cert) + pem_cert(certs.ca_cert))


# ---------------------------------------------------------------------------
# T14: demó és tesztek
# ---------------------------------------------------------------------------


def _t14_read_exact(conn: T14Connection, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = conn.read_app(length - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _t14_run_pair(server_config: T14Config, client_config: T14Config,
                  server_action, client_action) -> dict[str, Any]:
    left, right = socket.socketpair()
    results: dict[str, Any] = {
        "server": None,
        "server_error": None,
        "client": None,
        "client_error": None,
    }

    def server_run() -> None:
        try:
            server = T14Server(right, server_config)
            server.handshake()
            results["server"] = server_action(server)
        except BaseException as exc:  # a teszt kimenetéhez elkapjuk
            results["server_error"] = exc
        finally:
            try:
                right.close()
            except OSError:
                pass

    thread = threading.Thread(target=server_run, daemon=True)
    thread.start()
    try:
        client = T14Client(left, client_config)
        client.handshake()
        results["client"] = client_action(client)
    except BaseException as exc:
        results["client_error"] = exc
    finally:
        try:
            left.close()
        except OSError:
            pass
    thread.join(timeout=10)
    if thread.is_alive():
        raise T14Error("test pair timed out")
    return results


def _t14_echo_server(server: T14Server) -> dict[str, Any]:
    received = bytearray()
    while True:
        chunk = server.read_app(4096)
        if not chunk:
            break
        received.extend(chunk)
        server.write_app(chunk)
    result = {
        "received": bytes(received),
        "alpn": server.alpn,
        "sni": server.sni,
        "suite": t14_suite_name(server.cipher_suite),
    }
    server.close()
    return result


def _t14_exchange_client(client: T14Client, messages: list[bytes],
                         key_update_after: int | None = None) -> dict[str, Any]:
    replies = []
    for index, message in enumerate(messages):
        if key_update_after is not None and index == key_update_after:
            client.key_update(True)
        client.write_app(message)
        replies.append(_t14_read_exact(client, len(message)))
    result = {
        "replies": replies,
        "alpn": client.alpn,
        "sni": client.sni,
        "suite": t14_suite_name(client.cipher_suite),
    }
    client.close()
    return result


def _t14_expect_alert(results: dict[str, Any], description: int,
                      label: str) -> None:
    error = results["client_error"]
    if not isinstance(error, T14Alert) or error.description != description:
        raise AssertionError(
            f"{label}: expected client alert {description}, got {error!r} "
            f"(server: {results['server_error']!r})"
        )


def t14_demo() -> int:
    print("TLS 1.4 / hybrid demo")
    certs = t14_generate_test_certs()
    print("  test CA, server, RSA client, ECDSA P-256 client certificates generated")

    base_server = T14Config(
        ca_chain=[certs.ca_der],
        cert_chain=certs.server_chain,
        private_key=certs.server_key,
        alpn_protocols=["http/1.1", "h2"],
    )

    # 1. Alap kézfogás AES-128-cal, SNI/ALPN, majd KeyUpdate mindkét irányban.
    client_cfg = T14Config(
        ca_chain=[certs.ca_der],
        server_name="localhost",
        alpn_protocols=["http/1.1"],
        cipher_suites=[T14Suite.AES_128_GCM_SHA256],
    )
    messages = [b"hello from TLS 1.4 hybrid client\n", b"after key update\n"]
    results = _t14_run_pair(
        base_server, client_cfg,
        _t14_echo_server,
        lambda c: _t14_exchange_client(c, messages, key_update_after=1),
    )
    if results["client_error"] or results["server_error"]:
        raise AssertionError(
            f"basic handshake failed: {results['client_error']!r} / "
            f"{results['server_error']!r}"
        )
    assert results["client"]["replies"] == messages
    assert results["server"]["received"] == b"".join(messages)
    assert results["client"]["alpn"] == "http/1.1"
    assert results["server"]["sni"] == "localhost"
    assert results["server"]["suite"] == "TLS_AES_128_GCM_SHA256"
    print("  [1] AES-128-GCM + ALPN + SNI + KeyUpdate ............. OK")

    # 2. AES-256-GCM + kötelező RSA klienshitelesítés.
    server_cfg = dataclasses.replace(
        base_server,
        request_client_certificate=True,
        require_client_certificate=True,
        cipher_suites=[T14Suite.AES_256_GCM_SHA384],
    )
    client_cfg = T14Config(
        ca_chain=[certs.ca_der],
        server_name="localhost",
        alpn_protocols=["http/1.1"],
        cert_chain=certs.client_chain,
        private_key=certs.client_key,
        cipher_suites=[T14Suite.AES_256_GCM_SHA384],
    )
    results = _t14_run_pair(
        server_cfg, client_cfg,
        _t14_echo_server,
        lambda c: _t14_exchange_client(c, [b"client auth RSA\n"]),
    )
    if results["client_error"] or results["server_error"]:
        raise AssertionError(
            f"RSA client auth failed: {results['client_error']!r} / "
            f"{results['server_error']!r}"
        )
    assert results["client"]["replies"] == [b"client auth RSA\n"]
    assert results["server"]["suite"] == "TLS_AES_256_GCM_SHA384"
    print("  [2] AES-256-GCM + RSA klienshitelesítés ............... OK")

    # 3. ECDSA P-256 klienshitelesítés.
    client_cfg = T14Config(
        ca_chain=[certs.ca_der],
        server_name="localhost",
        alpn_protocols=["h2"],
        cert_chain=certs.client_ec_chain,
        private_key=certs.client_ec_key,
    )
    results = _t14_run_pair(
        server_cfg, client_cfg,
        _t14_echo_server,
        lambda c: _t14_exchange_client(c, [b"client auth ECDSA\n"]),
    )
    if results["client_error"] or results["server_error"]:
        raise AssertionError(
            f"ECDSA client auth failed: {results['client_error']!r} / "
            f"{results['server_error']!r}"
        )
    assert results["client"]["replies"] == [b"client auth ECDSA\n"]
    print("  [3] AES-256-GCM + ECDSA P-256 klienshitelesítés ....... OK")

    # 4. Negatív: hostname mismatch.
    bad_client = T14Config(
        ca_chain=[certs.ca_der],
        server_name="wrong.example",
        alpn_protocols=["http/1.1"],
    )
    results = _t14_run_pair(
        base_server, bad_client, _t14_echo_server,
        lambda c: _t14_exchange_client(c, [b"x"]),
    )
    _t14_expect_alert(results, T14_ALERT_BAD_CERTIFICATE, "hostname mismatch")
    print("  [4] hostname mismatch elutasítva ..................... OK")

    # 5. Negatív: hiányos keyUsage/EKU a szervertanúsítványon.
    bad_server = dataclasses.replace(
        base_server, cert_chain=certs.bad_server_chain
    )
    plain_client = T14Config(
        ca_chain=[certs.ca_der],
        server_name="localhost",
        alpn_protocols=["http/1.1"],
    )
    results = _t14_run_pair(
        bad_server, plain_client,
        _t14_echo_server,
        lambda c: _t14_exchange_client(c, [b"x"]),
    )
    _t14_expect_alert(results, T14_ALERT_BAD_CERTIFICATE,
                      "bad server certificate")
    print("  [5] hiányos keyUsage/EKU elutasítva .................. OK")

    # 6. Negatív: kötelező kliens-tanúsítvány hiánya.
    no_cert_client = T14Config(
        ca_chain=[certs.ca_der],
        server_name="localhost",
        alpn_protocols=["http/1.1"],
        cipher_suites=[T14Suite.AES_256_GCM_SHA384],
    )
    results = _t14_run_pair(
        server_cfg, no_cert_client, _t14_echo_server,
        lambda c: _t14_exchange_client(c, [b"x"]),
    )
    _t14_expect_alert(results, T14_ALERT_CERTIFICATE_REQUIRED,
                      "missing client certificate")
    print("  [6] hiányzó kötelező kliens-tanúsítvány .............. OK")

    # 7. Negatív: nincs közös ALPN.
    h2_server = dataclasses.replace(base_server, alpn_protocols=["h2"])
    http_client = T14Config(
        ca_chain=[certs.ca_der],
        server_name="localhost",
        alpn_protocols=["http/1.1"],
    )
    results = _t14_run_pair(
        h2_server, http_client, _t14_echo_server,
        lambda c: _t14_exchange_client(c, [b"x"]),
    )
    _t14_expect_alert(results, T14_ALERT_NO_APPLICATION_PROTOCOL,
                      "ALPN mismatch")
    print("  [7] ALPN egyeztetés hiánya elutasítva ................ OK")

    # 8. Negatív: nem megbízható CA.
    untrusted_client = T14Config(
        ca_chain=[certs.client_der],  # nem CA, nem a szerver kibocsátója
        server_name="localhost",
        alpn_protocols=["http/1.1"],
    )
    results = _t14_run_pair(
        base_server, untrusted_client, _t14_echo_server,
        lambda c: _t14_exchange_client(c, [b"x"]),
    )
    _t14_expect_alert(results, T14_ALERT_BAD_CERTIFICATE, "untrusted CA")
    print("  [8] nem megbízható CA elutasítva ..................... OK")

    # 9. Rekordréteg: tamper és key update.
    secret = b"\x42" * 32
    writer = T14RecordLayer()
    reader = T14RecordLayer()
    writer.install_write_keys(
        t14_derive_record_keys(T14Suite.AES_128_GCM_SHA256, secret)
    )
    reader.install_read_keys(
        t14_derive_record_keys(T14Suite.AES_128_GCM_SHA256, secret)
    )
    record = bytearray(writer.seal(T14_CT_APPLICATION_DATA, b"record"))
    record[-1] ^= 0x01
    try:
        reader.open(bytes(record))
    except T14Error:
        pass
    else:
        raise AssertionError("tampered record accepted")
    writer.update_write_keys()
    reader.update_read_keys()
    assert reader.open(writer.seal(T14_CT_APPLICATION_DATA,
                                   b"after update")).content == b"after update"
    print("  [9] AES-GCM tamper + KeyUpdate ....................... OK")

    # 10. Szerver által kezdeményezett KeyUpdate.
    def server_key_update(server: T14Server) -> bytes:
        server.key_update(True)
        server.write_app(b"tick")
        received = bytearray()
        while True:
            chunk = server.read_app(4096)
            if not chunk:
                break
            received.extend(chunk)
            server.write_app(chunk)
        server.close()
        return bytes(received)

    def client_key_update(client: T14Client) -> bytes:
        assert client.read_app(4) == b"tick"
        client.write_app(b"data")
        reply = _t14_read_exact(client, 4)
        client.close()
        return reply

    results = _t14_run_pair(
        base_server,
        T14Config(ca_chain=[certs.ca_der], server_name="localhost",
                  alpn_protocols=["http/1.1"]),
        server_key_update, client_key_update,
    )
    if results["client_error"] or results["server_error"]:
        raise AssertionError(
            f"server KeyUpdate failed: {results['client_error']!r} / "
            f"{results['server_error']!r}"
        )
    assert results["server"] == b"data"
    assert results["client"] == b"data"
    print("  [10] szerver oldali KeyUpdate ........................ OK")

    print("  TLS 1.4 demo: minden forgatókönyv OK")
    return 0


def t14_selftest() -> int:
    certs = t14_generate_test_certs()
    verifier = T14CertificateVerifier([certs.ca_der])
    server_chain = T14CertificateChain(certificates=certs.server_chain)
    client_chain = T14CertificateChain(certificates=certs.client_chain)
    verifier.verify_server(server_chain, "localhost")
    verifier.verify_server(server_chain, "127.0.0.1")
    verifier.verify_client(client_chain)
    try:
        verifier.verify_server(server_chain, "wrong.example")
    except T14Error:
        pass
    else:
        raise AssertionError("hostname mismatch accepted")

    # HKDF RFC 5869 1. tesztvektor (SHA-256).
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = t14_hkdf_extract(T14Hash.SHA256, salt, ikm)
    assert prk.hex() == (
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    okm = t14_hkdf_expand(T14Hash.SHA256, prk, info, 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    # NIST AES-128-GCM ismert vektor (96 bites nonce, üres AAD).
    key = bytes.fromhex("00000000000000000000000000000000")
    nonce = bytes.fromhex("000000000000000000000000")
    ct = t14_aes_gcm_seal(key, nonce, b"", bytes(16))
    assert ct.hex() == (
        "0388dace60b6a392f328c2b971b2fe78"
        "ab6e47d42cec13bdf53a67b21257bddf"
    )
    assert t14_aes_gcm_open(key, nonce, b"", ct) == bytes(16)

    # RSA-OAEP és RSA-PSS roundtrip.
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = b"hybrid secret"
    blob = t14_rsa_oaep_encrypt(rsa_key.public_key(), message)
    assert t14_rsa_oaep_decrypt(rsa_key, blob) == message
    signature = t14_sign_with_scheme(
        rsa_key, T14SignatureScheme.RSA_PSS_RSAE_SHA256, message
    )
    assert t14_verify_with_scheme(
        rsa_key.public_key(), T14SignatureScheme.RSA_PSS_RSAE_SHA256,
        message, signature,
    )
    signature = t14_sign_with_scheme(
        rsa_key, T14SignatureScheme.RSA_PSS_RSAE_SHA384, message
    )
    assert t14_verify_with_scheme(
        rsa_key.public_key(), T14SignatureScheme.RSA_PSS_RSAE_SHA384,
        message, signature,
    )

    # ECDSA P-256 roundtrip.
    ec_key = ec.generate_private_key(ec.SECP256R1())
    signature = t14_sign_with_scheme(
        ec_key, T14SignatureScheme.ECDSA_SECP256R1_SHA256, message
    )
    assert t14_verify_with_scheme(
        ec_key.public_key(), T14SignatureScheme.ECDSA_SECP256R1_SHA256,
        message, signature,
    )

    # X25519 közös titok.
    alice = t14_x25519_generate()
    bob = t14_x25519_generate()
    assert (t14_x25519_derive(alice, t14_x25519_public(bob))
            == t14_x25519_derive(bob, t14_x25519_public(alice)))

    print("TLS 1.4 selftest: OK (X.509, HKDF, AES-GCM, RSA, ECDSA, X25519)")
    return 0


# ===========================================================================
# TLS 1.5 -- TowerStack/1.5
# ===========================================================================
#
# Oktató mock, NEM production crypto. X25519 + ML-KEM-768, ML-DSA-65,
# háromrétegű stack (AES-GCM / ChaCha20-Poly1305 / AES-CTR+HMAC-SHA-384),
# epoch- és sequence-fegyelem, irányonkénti kulcsok, sliding replay ablak,
# AAD-transcript kötés, egységes hiba, méretlimitek, padding, rekey.
# ===========================================================================

T15_MAGIC = b"T15"
T15_VERSION = 1
T15_TAG = 16
T15_MAC = 32
T15_PAD = 128
T15_FRAME_HDR = 5
T15_MAX_FRAME = 64 * 1024
T15_MAX_WIRE = 64 * 1024 + 256
T15_MAX_PLAINTEXT = 60_000
T15_MAX_SEQ = 2 ** 32


class TowerError(Exception):
    """Egyetlen kifelé látható hiba. Részleteket csak belső logba írj."""


@dataclass(frozen=True)
class TowerSuite:
    suite_id: int
    kem: str
    l1: str
    l2: str
    l3: str


T15_SUITE = TowerSuite(
    0x1501,
    "X25519 + ML-KEM-768",
    "AES-256-GCM",
    "ChaCha20-Poly1305",
    "AES-256-CTR + HMAC-SHA-384",
)
T15_SUITES = {T15_SUITE.suite_id: T15_SUITE}


@dataclass(frozen=True)
class T15Frame:
    layer: int
    body: bytes

    def encode(self) -> bytes:
        if len(self.body) > T15_MAX_FRAME:
            raise TowerError("frame too large")
        return struct.pack(">B I", self.layer, len(self.body)) + self.body

    @classmethod
    def decode(cls, raw: bytes) -> "T15Frame":
        if len(raw) < T15_FRAME_HDR:
            raise TowerError("short frame")
        layer, n = struct.unpack(">B I", raw[:T15_FRAME_HDR])
        if n > T15_MAX_FRAME:
            raise TowerError("frame too large")
        if len(raw) != T15_FRAME_HDR + n:
            raise TowerError("bad frame length")
        return cls(layer, raw[T15_FRAME_HDR:])


def t15_nonce12(epoch: int, seq: int) -> bytes:
    if not 0 <= epoch < 2 ** 32:
        raise TowerError("epoch overflow")
    if not 0 <= seq < 2 ** 64:
        raise TowerError("sequence overflow")
    return struct.pack(">I Q", epoch, seq)


class T15ReplayWindow:
    """Sliding window; csak sikeres L1 hitelesítés után hívd."""

    def __init__(self, size: int = 64):
        if not 0 < size <= 64:
            raise ValueError("bad replay window size")
        self.size = size
        self.max_seq = -1
        self.bits = 0

    def check_and_update(self, seq: int) -> None:
        if seq < 0:
            raise TowerError("negative sequence")
        if seq > self.max_seq:
            shift = seq - self.max_seq
            if shift >= self.size:
                self.bits = 1
            else:
                self.bits = ((self.bits << shift) | 1) & ((1 << self.size) - 1)
            self.max_seq = seq
        else:
            diff = self.max_seq - seq
            if diff >= self.size:
                raise TowerError("too old")
            mask = 1 << diff
            if self.bits & mask:
                raise TowerError("replay")
            self.bits |= mask


@dataclass(frozen=True)
class T15Header:
    version: int
    suite: int
    epoch: int
    seq: int
    direction: int
    wire_len: int

    def encode(self) -> bytes:
        return struct.pack(
            ">3s B H I Q B I",
            T15_MAGIC, self.version, self.suite, self.epoch,
            self.seq, self.direction, self.wire_len,
        )

    @classmethod
    def decode(cls, data: bytes) -> tuple["T15Header", bytes]:
        if len(data) < 23:
            raise TowerError("short outer header")
        magic, version, suite, epoch, seq, direction, wire_len = struct.unpack(
            ">3s B H I Q B I", data[:23]
        )
        if magic != T15_MAGIC or version != T15_VERSION:
            raise TowerError("bad magic/version")
        if wire_len < T15_TAG + 3:
            raise TowerError("short packet")
        if wire_len > T15_MAX_WIRE:
            raise TowerError("wire packet too large")
        if len(data) != 23 + wire_len:
            raise TowerError("bad framing")
        return (cls(version, suite, epoch, seq, direction, wire_len),
                data[23:])

    def aad(self, transcript: bytes, layer: int, n: int) -> bytes:
        return (
            struct.pack(
                ">3s B H I Q B I B I",
                T15_MAGIC, self.version, self.suite, self.epoch,
                self.seq, self.direction, self.wire_len, layer, n,
            )
            + transcript
        )


class AEADLayer:
    """L1 vagy L2: a belső Frame-et AEAD-dal csomagolja."""

    def __init__(self, layer_id: int, inner_id: int, key: bytes, aead_cls):
        self.layer_id = layer_id
        self.inner_id = inner_id
        self.aead = aead_cls(key)

    def seal(self, inner: T15Frame, header: T15Header, nonce: bytes,
             transcript: bytes) -> T15Frame:
        if inner.layer != self.inner_id:
            raise TowerError("stack order on seal")
        plain = inner.encode()
        n = len(plain)
        ct = self.aead.encrypt(
            nonce, plain, header.aad(transcript, self.layer_id, n)
        )
        return T15Frame(self.layer_id, ct)

    def open(self, outer: T15Frame, header: T15Header, nonce: bytes,
             transcript: bytes) -> T15Frame:
        if outer.layer != self.layer_id:
            raise TowerError("stack order on open")
        if len(outer.body) < T15_TAG + T15_FRAME_HDR:
            raise TowerError("short AEAD frame")
        n = len(outer.body) - T15_TAG
        plain = self.aead.decrypt(
            nonce, outer.body, header.aad(transcript, self.layer_id, n)
        )
        inner = T15Frame.decode(plain)
        if inner.layer != self.inner_id:
            raise TowerError("inner layer mismatch")
        return inner


class StreamHMACLayer:
    """L3: AES-256-CTR + HMAC-SHA-384, encrypt-then-MAC."""

    def __init__(self, layer_id: int, inner_id: int, enc_key: bytes,
                 mac_key: bytes):
        self.layer_id = layer_id
        self.inner_id = inner_id
        self.enc_key = enc_key
        self.mac_key = mac_key

    def _cipher(self, nonce: bytes) -> Cipher:
        return Cipher(algorithms.AES(self.enc_key),
                      modes.CTR(nonce + b"\0\0\0\0"))

    def seal(self, inner: T15Frame, header: T15Header, nonce: bytes,
             transcript: bytes) -> T15Frame:
        if inner.layer != self.inner_id:
            raise TowerError("stack order on seal")
        plain = inner.encode()
        encryptor = self._cipher(nonce).encryptor()
        ct = encryptor.update(plain) + encryptor.finalize()
        tag = hmac.new(
            self.mac_key,
            header.aad(transcript, self.layer_id, len(ct)) + ct,
            hashlib.sha384,
        ).digest()[:T15_MAC]
        return T15Frame(self.layer_id, ct + tag)

    def open(self, outer: T15Frame, header: T15Header, nonce: bytes,
             transcript: bytes) -> T15Frame:
        if outer.layer != self.layer_id:
            raise TowerError("stack order on open")
        if len(outer.body) < T15_MAC + T15_FRAME_HDR:
            raise TowerError("short L3 frame")
        ct, tag = outer.body[:-T15_MAC], outer.body[-T15_MAC:]
        want = hmac.new(
            self.mac_key,
            header.aad(transcript, self.layer_id, len(ct)) + ct,
            hashlib.sha384,
        ).digest()[:T15_MAC]
        if not hmac.compare_digest(tag, want):
            raise TowerError("L3 MAC failure")
        decryptor = self._cipher(nonce).decryptor()
        plain = decryptor.update(ct) + decryptor.finalize()
        inner = T15Frame.decode(plain)
        if inner.layer != self.inner_id:
            raise TowerError("inner layer mismatch")
        return inner


class T15Layer(Protocol):
    layer_id: int
    inner_id: int

    def seal(self, inner: T15Frame, header: T15Header, nonce: bytes,
             transcript: bytes) -> T15Frame: ...

    def open(self, outer: T15Frame, header: T15Header, nonce: bytes,
             transcript: bytes) -> T15Frame: ...


class TowerStack:
    """LIFO stack: [L3, L2, L1]. push = seal, pop = open."""

    def __init__(self, layers: list[T15Layer]):
        if not layers:
            raise TowerError("empty tower")
        for lower, upper in zip(layers, layers[1:]):
            if upper.inner_id != lower.layer_id:
                raise TowerError("layers are not adjacent")
        self.layers = list(layers)

    def push(self, frame: T15Frame, header: T15Header, nonce: bytes,
             transcript: bytes) -> T15Frame:
        for layer in self.layers:
            frame = layer.seal(frame, header, nonce, transcript)
        return frame

    def pop(self, frame: T15Frame, header: T15Header, nonce: bytes,
            transcript: bytes, after_l1=None) -> T15Frame:
        for index, layer in enumerate(reversed(self.layers)):
            frame = layer.open(frame, header, nonce, transcript)
            if index == 0 and after_l1 is not None:
                after_l1(frame)
        return frame


@dataclass(frozen=True)
class T15TrafficKeys:
    l1: bytes
    l2: bytes
    l3_enc: bytes
    l3_mac: bytes


@dataclass(frozen=True)
class T15HandshakeKeys:
    suite: TowerSuite
    master: bytes
    transcript: bytes
    c2s: T15TrafficKeys
    s2c: T15TrafficKeys
    c2s_finished: bytes
    s2c_finished: bytes


def t15_expand_label(secret: bytes, label: bytes, context: bytes,
                     n: int) -> bytes:
    full = b"tower-stack/1.5 " + label
    info = (
        struct.pack(">H", n)
        + bytes([len(full)])
        + full
        + bytes([len(context)])
        + context
    )
    return HKDFExpand(hashes.SHA256(), n, info).derive(secret)


def t15_derive_master(shared: bytes, th1: bytes) -> tuple[bytes, bytes, bytes]:
    master = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\x00" * 32,
        info=b"tower-stack/1.5 master" + th1,
    ).derive(shared)
    c2s_finished = t15_expand_label(master, b"finished c2s", th1, 32)
    s2c_finished = t15_expand_label(master, b"finished s2c", th1, 32)
    return master, c2s_finished, s2c_finished


def t15_derive_traffic(master: bytes, transcript: bytes,
                       epoch: int) -> tuple[T15TrafficKeys, T15TrafficKeys]:
    ctx = transcript + struct.pack(">I", epoch)

    def ks(direction: bytes) -> T15TrafficKeys:
        return T15TrafficKeys(
            l1=t15_expand_label(master, direction + b" l1", ctx, 32),
            l2=t15_expand_label(master, direction + b" l2", ctx, 32),
            l3_enc=t15_expand_label(master, direction + b" l3-enc", ctx, 32),
            l3_mac=t15_expand_label(master, direction + b" l3-mac", ctx, 48),
        )

    return ks(b"c2s"), ks(b"s2c")


def t15_make_stack(keys: T15TrafficKeys) -> TowerStack:
    return TowerStack([
        StreamHMACLayer(3, 0, keys.l3_enc, keys.l3_mac),
        AEADLayer(2, 3, keys.l2, ChaCha20Poly1305),
        AEADLayer(1, 2, keys.l1, AESGCM),
    ])


@dataclass(frozen=True)
class T15ClientHello:
    client_random: bytes
    x25519_pub: bytes
    mlkem_pub: bytes
    offers: tuple[int, ...]
    version: int = T15_VERSION

    def encode(self) -> bytes:
        if len(self.client_random) != 32 or len(self.x25519_pub) != 32:
            raise TowerError("bad client hello")
        if len(self.offers) > 255:
            raise TowerError("too many suites")
        return (
            b"CH"
            + struct.pack(">B", self.version)
            + self.client_random
            + self.x25519_pub
            + struct.pack(">H", len(self.mlkem_pub))
            + self.mlkem_pub
            + bytes([len(self.offers)])
            + b"".join(struct.pack(">H", s) for s in self.offers)
        )


@dataclass(frozen=True)
class T15ServerHello:
    server_random: bytes
    x25519_pub: bytes
    mlkem_ct: bytes
    selected_suite: int
    signature: bytes
    version: int = T15_VERSION

    def prefix(self) -> bytes:
        return (
            b"SH"
            + struct.pack(">B", self.version)
            + self.server_random
            + self.x25519_pub
            + struct.pack(">H", len(self.mlkem_ct))
            + self.mlkem_ct
            + struct.pack(">H", self.selected_suite)
        )

    def encode(self) -> bytes:
        if len(self.signature) > 0xFFFF:
            raise TowerError("signature too large")
        return (self.prefix()
                + struct.pack(">H", len(self.signature))
                + self.signature)


def t15_negotiate(offers: tuple[int, ...],
                  policy: tuple[TowerSuite, ...]) -> TowerSuite:
    allowed = {s.suite_id: s for s in policy}
    for suite_id in offers:
        if suite_id in allowed:
            return allowed[suite_id]
    raise TowerError("no common tower suite")


def t15_make_client_hello(offers: tuple[int, ...]):
    x_priv = x25519.X25519PrivateKey.generate()
    kem_priv = mlkem.MLKEM768PrivateKey.generate()
    ch = T15ClientHello(
        client_random=os.urandom(32),
        x25519_pub=x_priv.public_key().public_bytes_raw(),
        mlkem_pub=kem_priv.public_key().public_bytes_raw(),
        offers=tuple(offers),
    )
    return ch, x_priv, kem_priv


def t15_server_accept(ch: T15ClientHello,
                      server_sign_key,
                      policy: tuple[TowerSuite, ...]):
    """Returns (ServerHello, server Finished MAC, handshake keys)."""
    if ch.version != T15_VERSION:
        raise TowerError("unsupported handshake version")
    suite = t15_negotiate(ch.offers, policy)
    server_x = x25519.X25519PrivateKey.generate()
    client_kem_pub = mlkem.MLKEM768PublicKey.from_public_bytes(ch.mlkem_pub)
    mlkem_ss, mlkem_ct = client_kem_pub.encapsulate()

    sh_unsigned = T15ServerHello(
        server_random=os.urandom(32),
        x25519_pub=server_x.public_key().public_bytes_raw(),
        mlkem_ct=mlkem_ct,
        selected_suite=suite.suite_id,
        signature=b"",
    )
    th1 = hashlib.sha256(ch.encode() + sh_unsigned.prefix()).digest()
    signature = server_sign_key.sign(th1)
    sh = T15ServerHello(
        server_random=sh_unsigned.server_random,
        x25519_pub=sh_unsigned.x25519_pub,
        mlkem_ct=sh_unsigned.mlkem_ct,
        selected_suite=sh_unsigned.selected_suite,
        signature=signature,
    )

    x_ss = server_x.exchange(
        x25519.X25519PublicKey.from_public_bytes(ch.x25519_pub)
    )
    shared = x_ss + mlkem_ss
    master, c2s_finished, s2c_finished = t15_derive_master(shared, th1)
    server_finished = hmac.new(
        s2c_finished, b"tower finished" + bytes([1]) + th1, hashlib.sha256
    ).digest()
    th2 = hashlib.sha256(th1 + server_finished).digest()
    c2s, s2c = t15_derive_traffic(master, th2, 0)
    hk = T15HandshakeKeys(suite, master, th2, c2s, s2c,
                          c2s_finished, s2c_finished)
    return sh, server_finished, hk


def t15_client_accept(ch: T15ClientHello,
                      ch_x,
                      ch_kem,
                      sh: T15ServerHello,
                      server_verify_key,
                      server_finished: bytes):
    """Returns (client Finished MAC, handshake keys)."""
    if sh.version != T15_VERSION:
        raise TowerError("unsupported handshake version")
    if sh.selected_suite not in ch.offers:
        raise TowerError("server selected an unoffered suite")
    suite = T15_SUITES.get(sh.selected_suite)
    if suite is None:
        raise TowerError("unknown suite")

    th1 = hashlib.sha256(ch.encode() + sh.prefix()).digest()
    try:
        server_verify_key.verify(sh.signature, th1)
    except Exception:
        raise TowerError("server authentication failed") from None

    x_ss = ch_x.exchange(
        x25519.X25519PublicKey.from_public_bytes(sh.x25519_pub)
    )
    mlkem_ss = ch_kem.decapsulate(sh.mlkem_ct)
    shared = x_ss + mlkem_ss
    master, c2s_finished, s2c_finished = t15_derive_master(shared, th1)

    want_server = hmac.new(
        s2c_finished, b"tower finished" + bytes([1]) + th1, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(want_server, server_finished):
        raise TowerError("server Finished failed")

    th2 = hashlib.sha256(th1 + server_finished).digest()
    c2s, s2c = t15_derive_traffic(master, th2, 0)
    hk = T15HandshakeKeys(suite, master, th2, c2s, s2c,
                          c2s_finished, s2c_finished)

    client_finished = hmac.new(
        c2s_finished, b"tower finished" + bytes([0]) + th2, hashlib.sha256
    ).digest()
    return client_finished, hk


def t15_server_verify_client_finished(hk: T15HandshakeKeys,
                                      client_finished: bytes) -> None:
    want = hmac.new(
        hk.c2s_finished,
        b"tower finished" + bytes([0]) + hk.transcript,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(want, client_finished):
        raise TowerError("client Finished failed")


def t15_pad(pt: bytes) -> bytes:
    n = T15_PAD - (len(pt) % T15_PAD)
    return pt + bytes([n]) * n


def t15_unpad(padded: bytes) -> bytes:
    if not padded:
        raise TowerError("empty padding")
    n = padded[-1]
    if n < 1 or n > T15_PAD or n > len(padded) or padded[-n:] != bytes([n]) * n:
        raise TowerError("bad padding")
    return padded[:-n]


class TowerSession:
    def __init__(self, hk: T15HandshakeKeys, role: int):
        if role not in (0, 1):
            raise TowerError("bad role")
        self.role = role                    # 0 = client, 1 = server
        self.send_direction = role
        self.recv_direction = 1 - role
        self.suite = hk.suite
        self.master = hk.master
        self.transcript = hk.transcript
        self.epoch = 0
        self.c2s = hk.c2s
        self.s2c = hk.s2c
        self.stacks = {
            0: t15_make_stack(self.c2s),
            1: t15_make_stack(self.s2c),
        }
        self.send_seq = {0: 0, 1: 0}
        self.replay = {0: T15ReplayWindow(), 1: T15ReplayWindow()}

    def seal(self, plaintext: bytes) -> bytes:
        direction = self.send_direction
        if len(plaintext) > T15_MAX_PLAINTEXT:
            raise TowerError("fragment first")
        if self.send_seq[direction] >= T15_MAX_SEQ:
            raise TowerError("rekey required")

        seq = self.send_seq[direction]
        self.send_seq[direction] += 1
        padded = t15_pad(plaintext)
        p = len(padded)
        wire_len = p + 3 * T15_FRAME_HDR + T15_MAC + 2 * T15_TAG
        header = T15Header(T15_VERSION, self.suite.suite_id, self.epoch,
                           seq, direction, wire_len)
        nonce = t15_nonce12(self.epoch, seq)
        frame = self.stacks[direction].push(
            T15Frame(0, padded), header, nonce, self.transcript
        )
        if frame.layer != 1 or len(frame.body) != wire_len:
            raise TowerError("internal wire length mismatch")
        return header.encode() + frame.body

    def open(self, packet: bytes) -> bytes:
        try:
            header, l1_body = T15Header.decode(packet)
            if header.suite != self.suite.suite_id:
                raise TowerError("unsupported suite")
            if header.direction != self.recv_direction:
                raise TowerError("wrong direction")
            if header.epoch != self.epoch:
                raise TowerError("wrong epoch")
            if len(l1_body) != header.wire_len:
                raise TowerError("wire length mismatch")

            nonce = t15_nonce12(header.epoch, header.seq)
            frame = T15Frame(1, l1_body)
            frame = self.stacks[header.direction].pop(
                frame, header, nonce, self.transcript,
                after_l1=lambda _: self.replay[header.direction]
                .check_and_update(header.seq),
            )
            if frame.layer != 0:
                raise TowerError("top of stack is not plaintext")
            return t15_unpad(frame.body)
        except Exception:
            raise TowerError("decrypt failed") from None

    def rekey(self) -> None:
        if self.epoch >= 2 ** 32 - 1:
            raise TowerError("epoch exhausted")
        self.epoch += 1
        self.c2s, self.s2c = t15_derive_traffic(
            self.master, self.transcript, self.epoch
        )
        self.stacks = {0: t15_make_stack(self.c2s),
                       1: t15_make_stack(self.s2c)}
        self.send_seq = {0: 0, 1: 0}
        self.replay = {0: T15ReplayWindow(), 1: T15ReplayWindow()}


def t15_demo() -> int:
    _require_crypto()
    print("TLS 1.5 / TowerStack demo")
    server_sign = mldsa.MLDSA65PrivateKey.generate()
    server_verify = server_sign.public_key()
    print(f"  suite        : {T15_SUITE.kem} / {T15_SUITE.l1} / "
          f"{T15_SUITE.l2} / {T15_SUITE.l3}")

    ch, ch_x, ch_kem = t15_make_client_hello((T15_SUITE.suite_id,))
    sh, server_finished, server_hk = t15_server_accept(
        ch, server_sign, (T15_SUITE,)
    )
    client_finished, client_hk = t15_client_accept(
        ch, ch_x, ch_kem, sh, server_verify, server_finished
    )
    t15_server_verify_client_finished(server_hk, client_finished)

    client = TowerSession(client_hk, role=0)
    server = TowerSession(server_hk, role=1)

    wire = client.seal(b"hello through the tower")
    assert server.open(wire) == b"hello through the tower"
    print("  handshake + L1/L2/L3 record ....................... OK")

    try:
        client.open(wire)
    except TowerError:
        print("  reflection rejected ............................... OK")
    else:
        raise AssertionError("reflected packet accepted")

    reply = server.seal(b"reply")
    assert client.open(reply) == b"reply"

    bad = bytearray(client.seal(b"tamper me"))
    bad[-1] ^= 1
    try:
        server.open(bytes(bad))
    except TowerError as exc:
        print(f"  tamper rejected: {exc} .................... OK")
    else:
        raise AssertionError("tampered packet accepted")

    replay = client.seal(b"replay me")
    assert server.open(replay) == b"replay me"
    try:
        server.open(replay)
    except TowerError as exc:
        print(f"  replay rejected: {exc} .................... OK")
    else:
        raise AssertionError("replayed packet accepted")

    client.rekey()
    server.rekey()
    after = client.seal(b"after rekey")
    assert server.open(after) == b"after rekey"
    print("  rekey + új epoch .................................. OK")

    try:
        server.open(wire)
    except TowerError:
        print("  old epoch rejected ................................ OK")
    else:
        raise AssertionError("old epoch accepted")

    print(f"  wire bytes: {len(wire)}")
    print("  TLS 1.5 demo: OK")
    return 0


def t15_selftest() -> int:
    _require_crypto()

    # Replay ablak.
    window = T15ReplayWindow(size=8)
    for seq in range(8):
        window.check_and_update(seq)
    try:
        window.check_and_update(7)
    except TowerError:
        pass
    else:
        raise AssertionError("replay window accepted duplicate")
    window.check_and_update(9)

    # Padding roundtrip és hibás padding.
    for length in (0, 1, 127, 128, 1000):
        assert t15_unpad(t15_pad(b"x" * length)) == b"x" * length
    try:
        t15_unpad(b"\x00" * 4)
    except TowerError:
        pass
    else:
        raise AssertionError("bad padding accepted")

    # Teljes handshake + record + rekey.
    server_sign = mldsa.MLDSA65PrivateKey.generate()
    ch, ch_x, ch_kem = t15_make_client_hello((T15_SUITE.suite_id,))
    sh, server_finished, server_hk = t15_server_accept(
        ch, server_sign, (T15_SUITE,)
    )
    client_finished, client_hk = t15_client_accept(
        ch, ch_x, ch_kem, sh, server_sign.public_key(), server_finished
    )
    t15_server_verify_client_finished(server_hk, client_finished)
    c = TowerSession(client_hk, 0)
    s = TowerSession(server_hk, 1)
    packet = c.seal(b"selftest")
    assert s.open(packet) == b"selftest"
    c.rekey()
    s.rekey()
    assert s.open(c.seal(b"epoch1")) == b"epoch1"

    print("TLS 1.5 selftest: OK (replay ablak, padding, handshake, rekey)")
    return 0


# ---------------------------------------------------------------------------
# T14: parancssori szerver/kliens
# ---------------------------------------------------------------------------


def _t14_suite_from_arg(value: str) -> T14Suite:
    if value == "128":
        return T14Suite.AES_128_GCM_SHA256
    if value == "256":
        return T14Suite.AES_256_GCM_SHA384
    raise argparse.ArgumentTypeError("--suite must be 128 or 256")


def t14_cmd_gen_certs(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="tls_versions.py 1.4 gen-certs",
        description="Teszt CA és tanúsítványok generálása (PEM).",
    )
    parser.add_argument("directory", nargs="?", default="certs")
    args = parser.parse_args(argv)
    t14_write_cert_files(args.directory)
    print(f"tanúsítványok kiírva: {Path(args.directory).resolve()}")
    for name in ("ca.crt", "ca.key", "server.crt", "server.key",
                 "server-chain.crt", "client.crt", "client.key",
                 "client-chain.crt", "client-ec.crt", "client-ec.key",
                 "client-ec-chain.crt", "bad-server.crt",
                 "bad-server-chain.crt"):
        print(f"  {name}")
    return 0


def t14_cmd_server(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="tls_versions.py 1.4 server",
        description="TLS 1.4 hybrid echo szerver.",
    )
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--cert-dir", default="certs")
    parser.add_argument("--alpn", default="http/1.1",
                        help="vesszővel elválasztott ALPN lista")
    parser.add_argument("--suite", choices=["128", "256"])
    parser.add_argument("--client-cert", action="store_true")
    parser.add_argument("--require-client-cert", action="store_true")
    parser.add_argument("--loop", action="store_true")
    args = parser.parse_args(argv)

    cert_dir = Path(args.cert_dir)
    ca_file = cert_dir / "ca.crt"
    alpn = [p for p in args.alpn.split(",") if p]
    suites = ([_t14_suite_from_arg(args.suite)] if args.suite
              else [T14Suite.AES_128_GCM_SHA256,
                    T14Suite.AES_256_GCM_SHA384])
    request_client = args.client_cert or args.require_client_cert
    if request_client and not ca_file.exists():
        print(f"server error: {ca_file} hiányzik a klienshitelesítéshez",
              file=sys.stderr)
        return 1

    try:
        config = t14_config_from_files(
            ca_file=str(ca_file) if ca_file.exists() else "",
            cert_file=str(cert_dir / "server-chain.crt"),
            key_file=str(cert_dir / "server.key"),
            alpn_protocols=alpn,
            cipher_suites=suites,
            request_client_certificate=request_client,
            require_client_certificate=args.require_client_cert,
        )
    except Exception as exc:
        print(f"server error: {exc}", file=sys.stderr)
        return 1

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((args.bind, args.port))
        listener.listen(8)
    except OSError as exc:
        print(f"server error: {exc}", file=sys.stderr)
        listener.close()
        return 1

    bound = listener.getsockname()[1]
    print(f"TLS 1.4 hybrid server listening on {args.bind}:{bound}")
    sys.stdout.flush()

    def handle(conn: socket.socket, peer: str) -> None:
        try:
            server = T14Server(conn, config)
            server.handshake()
            print(f"[{peer}] handshake complete: "
                  f"{t14_suite_name(server.cipher_suite)}, "
                  f"ALPN={server.alpn or '(none)'}, "
                  f"SNI={server.sni or '(none)'}")
            sys.stdout.flush()
            while True:
                data = server.read_app(1 << 14)
                if not data:
                    break
                server.write_app(data)
            server.close()
            print(f"[{peer}] connection closed")
            sys.stdout.flush()
        except Exception as exc:
            print(f"[{peer}] connection error: {exc}", file=sys.stderr)

    try:
        while True:
            conn, addr = listener.accept()
            peer = f"{addr[0]}:{addr[1]}"
            print(f"accepted connection from {peer}")
            sys.stdout.flush()
            if args.loop:
                threading.Thread(target=handle, args=(conn, peer),
                                 daemon=True).start()
            else:
                handle(conn, peer)
                break
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()
    return 0


def t14_cmd_client(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="tls_versions.py 1.4 client",
        description="TLS 1.4 hybrid echo kliens.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--cert-dir", default="certs")
    parser.add_argument("--server-name")
    parser.add_argument("--alpn", default="http/1.1")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--suite", choices=["128", "256"], default="128")
    parser.add_argument("--message",
                        default="hello from TLS 1.4 hybrid client\n")
    args = parser.parse_args(argv)

    cert_dir = Path(args.cert_dir)
    ca_file = cert_dir / "ca.crt"
    server_name = args.server_name or args.host
    try:
        config = t14_config_from_files(
            ca_file=str(ca_file),
            cert_file=args.cert or "",
            key_file=args.key or "",
            server_name=server_name,
            alpn_protocols=[args.alpn] if args.alpn else [],
            cipher_suites=[_t14_suite_from_arg(args.suite)],
        )
    except Exception as exc:
        print(f"client error: {exc}", file=sys.stderr)
        return 1

    try:
        sock = socket.create_connection((args.host, args.port), timeout=10)
    except OSError as exc:
        print(f"client error: connect failed: {exc}", file=sys.stderr)
        return 1

    try:
        client = T14Client(sock, config)
        client.handshake()
        print(f"handshake complete: {t14_suite_name(client.cipher_suite)}, "
              f"ALPN={client.alpn or '(none)'}, SNI={client.sni}")
        message = args.message.encode("utf-8")
        client.write_app(message)
        response = bytearray()
        while len(response) < len(message):
            chunk = client.read_app(512)
            if not chunk:
                break
            response.extend(chunk)
        print("server echoed: " + response.decode("utf-8", "replace"))
        client.close()
        return 0
    except Exception as exc:
        print(f"client error: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ===========================================================================
# Egységes parancssori felület
# ===========================================================================


def _run_all() -> int:
    t13_demo()
    print()
    t14_demo()
    print()
    t15_demo()
    return 0


def _run_selftest() -> int:
    t13_selftest()
    t14_selftest()
    t15_selftest()
    return 0


_HELP = """\
TLS 1.3 + 1.4 + 1.5 -- egyetlen Python szkript

Használat:
  python3 tls_versions.py                     # mindhárom demó
  python3 tls_versions.py all                 # mindhárom demó
  python3 tls_versions.py selftest            # mindhárom önteszt

  python3 tls_versions.py 1.3 demo            # TLS13-PQ demó
  python3 tls_versions.py 1.3 validate [JSON] # konfiguráció ellenőrzése
  python3 tls_versions.py 1.3 selftest

  python3 tls_versions.py 1.4 demo            # teljes TLS 1.4 demó
  python3 tls_versions.py 1.4 selftest
  python3 tls_versions.py 1.4 gen-certs DIR
  python3 tls_versions.py 1.4 server --port 4433 --cert-dir certs
  python3 tls_versions.py 1.4 client --host 127.0.0.1 --port 4433

  python3 tls_versions.py 1.5 demo            # TowerStack demó
  python3 tls_versions.py 1.5 selftest

A TLS 1.4/1.5 részekhez kell a 'cryptography' csomag.
"""


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return _run_all()

    command = args[0]
    if command in ("-h", "--help", "help"):
        print(_HELP)
        return 0
    if command in ("all",):
        return _run_all()
    if command in ("selftest", "test"):
        return _run_selftest()

    normalized = command.lower().replace("tls", "").replace(" ", "")
    if normalized in ("1.3", "13"):
        sub = args[1] if len(args) > 1 else "demo"
        rest = args[2:]
        if sub in ("demo", "run"):
            return t13_demo()
        if sub in ("validate", "check"):
            return t13_validate_command(rest[0] if rest else None)
        if sub in ("selftest", "test"):
            return t13_selftest()
        print(f"ismeretlen 1.3 parancs: {sub}", file=sys.stderr)
        return 2

    if normalized in ("1.4", "14"):
        sub = args[1] if len(args) > 1 else "demo"
        rest = args[2:]
        if sub in ("demo", "run"):
            return t14_demo()
        if sub in ("selftest", "test"):
            return t14_selftest()
        if sub in ("gen-certs", "gencerts", "certs"):
            return t14_cmd_gen_certs(rest)
        if sub == "server":
            return t14_cmd_server(rest)
        if sub == "client":
            return t14_cmd_client(rest)
        print(f"ismeretlen 1.4 parancs: {sub}", file=sys.stderr)
        return 2

    if normalized in ("1.5", "15"):
        sub = args[1] if len(args) > 1 else "demo"
        if sub in ("demo", "run"):
            return t15_demo()
        if sub in ("selftest", "test"):
            return t15_selftest()
        print(f"ismeretlen 1.5 parancs: {sub}", file=sys.stderr)
        return 2

    print(f"ismeretlen verzió: {command}\n", file=sys.stderr)
    print(_HELP, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

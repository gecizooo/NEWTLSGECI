"""TLS13-PQ: hybrid PQC, replay-safe 0-RTT, and hardened ECH.

Pure-Python reference model. No third-party dependencies.

Quick start::

    python3 demo.py
    python3 -m tls13pq validate example.json
    python3 -m unittest
"""

from __future__ import annotations

from .config import (
    Config,
    ConfigError,
    EarlyDataMode,
    FailMode,
    FilterKind,
    Group,
    OwnershipMode,
    Profile,
    SigScheme,
    default_hybrid,
    format_duration,
    from_dict,
    load_config,
    to_dict,
    validate,
)
from .early_data import (
    CommitStore,
    EarlyDataStatus,
    Outcome,
    ReplayFilter,
    Server,
    Ticket,
    commit_key,
)
from .handshake import ClientHello, HandshakeSimulator, ServerState, Session
from .padding import SizeEstimate, estimate_client_hello, pad_to_class, segments

__version__ = "0.1.0"

__all__ = [
    "Config",
    "ConfigError",
    "EarlyDataMode",
    "FailMode",
    "FilterKind",
    "Group",
    "OwnershipMode",
    "Profile",
    "SigScheme",
    "default_hybrid",
    "format_duration",
    "from_dict",
    "load_config",
    "to_dict",
    "validate",
    "CommitStore",
    "EarlyDataStatus",
    "Outcome",
    "ReplayFilter",
    "Server",
    "Ticket",
    "commit_key",
    "ClientHello",
    "HandshakeSimulator",
    "ServerState",
    "Session",
    "SizeEstimate",
    "estimate_client_hello",
    "pad_to_class",
    "segments",
    "__version__",
]

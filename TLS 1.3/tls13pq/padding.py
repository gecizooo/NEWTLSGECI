"""ECH padding schedule and handshake size arithmetic (spec Section 6.4).

All numbers are estimates for planning, not protocol constants. They exist so
the simulator can answer two questions:

* which padding class does this ClientHello land in?
* how many TCP segments does it occupy at a given MSS?

The important property is that the padded length is a function of the
*unpadded length class* only, never of the SNI itself.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .config import Group

__all__ = [
    "GROUP_SHARE_BYTES",
    "SizeEstimate",
    "estimate_client_hello",
    "pad_to_class",
    "segments",
]

# Client key_share sizes from the specification, Section 4.1.
GROUP_SHARE_BYTES: dict[Group, int] = {
    Group.X25519: 32,
    Group.SECP256R1: 65,
    Group.X25519_MLKEM768: 1216,
    Group.SECP256R1_MLKEM768: 1249,
    Group.X25519_MLKEM1024: 1600,
    Group.MLKEM768: 1184,
}

# Fixed overheads, deliberately conservative. Structure:
#   CHInner = base + key_share + SNI + optional guard
#   CHOuter = base_outer + HPKE(CHInner) + ECH extension
_BASE_INNER = 220
_BASE_OUTER = 160
_GUARD_BYTES = 18          # version(1) + mode(1) + commit_token(16)
_HPKE_OVERHEAD = 48        # enc(32) + AEAD tag(16)
_ECH_EXT = 20
_IP_TCP_HEADERS = 40


def pad_to_class(length: int, classes: list[int]) -> int:
    """Smallest class >= length; beyond the last class, round up to a multiple."""
    if length <= 0:
        raise ValueError("length must be positive")
    if not classes:
        raise ValueError("classes must not be empty")
    for cls in classes:
        if length <= cls:
            return cls
    last = classes[-1]
    return math.ceil(length / last) * last


def segments(length: int, mss: int = 1460) -> int:
    """TCP segments needed for ``length`` bytes, counting IP+TCP headers."""
    if length <= 0:
        return 0
    return math.ceil((length + _IP_TCP_HEADERS) / mss)


@dataclass(frozen=True)
class SizeEstimate:
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


def estimate_client_hello(group: Group, sni_length: int, *,
                          ech: bool, early_data: bool,
                          classes: list[int],
                          mss: int = 1460) -> SizeEstimate:
    """Estimate CHInner/CHOuter sizes and the resulting segment count.

    With ECH, the outer length is what gets padded to a class. The inner
    plaintext is then padded to *fill* that class minus the fixed HPKE and
    outer-header overhead, so the ciphertext length is constant within a class
    instead of revealing the inner length.
    """
    if group not in GROUP_SHARE_BYTES:
        raise ValueError(f"unknown group {group!r}")

    inner = _BASE_INNER + GROUP_SHARE_BYTES[group] + sni_length
    if early_data:
        inner += _GUARD_BYTES

    overhead = _BASE_OUTER + _HPKE_OVERHEAD + _ECH_EXT

    if ech:
        outer = _BASE_OUTER + inner + _HPKE_OVERHEAD + _ECH_EXT
        outer_padded = pad_to_class(outer, classes)
        inner_padded = outer_padded - overhead
        # The fill target can never be smaller than the real inner length,
        # because outer_padded >= outer.
        assert inner_padded >= inner
    else:
        inner_padded = pad_to_class(inner, classes)
        outer = inner
        outer_padded = inner_padded

    return SizeEstimate(
        inner=inner,
        inner_padded=inner_padded,
        outer=outer,
        outer_padded=outer_padded,
        segments=segments(outer_padded, mss),
        padding_class=outer_padded,
    )

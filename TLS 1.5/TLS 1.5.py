"""
TowerStack/1.5 v2 -- oktató mock, NEM production crypto.

A javítások sorrendje a kódban:
  STEP 1: hitelesített, 1-RTT handshake (X25519 + ML-KEM-768, ML-DSA-65)
  STEP 2: epoch / sequence / nonce fegyelem, rekey
  STEP 3: külön c2s/s2c kulcsok + sliding replay window
  STEP 4: AAD kötése a transcripthez, suite-hoz, epochhoz, irányhoz
  STEP 5: egységes hiba, méretlimitek, padding

FIGYELEM:
  - A handshake itt egyszerűsített: nincs X.509 lánc, nincs OCSP, nincs ALPN.
  - A hybrid KEM shared secret itt egyszerű konkatenáció; productionben
    szabványos hybrid combinert kell használni.
  - A "TowerStack/1.5" nem TLS, és nem használható éles rendszerben.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

MAGIC = b"T15"
VERSION = 1
TAG = 16
MAC = 32
PAD = 128
FRAME_HDR = 5
MAX_FRAME = 64 * 1024
MAX_WIRE = 64 * 1024 + 256
MAX_PLAINTEXT = 60_000
MAX_SEQ = 2**32  # AES-GCM message limit; rekey before this


# ---------------------------------------------------------------------------
# Errors, suite, frames
# ---------------------------------------------------------------------------

class TowerError(Exception):
    """Egyetlen kifelé látható hiba. Részleteket csak belső logba írj."""


@dataclass(frozen=True)
class TowerSuite:
    suite_id: int
    kem: str
    l1: str
    l2: str
    l3: str


SUITE = TowerSuite(
    0x1501,
    "X25519 + ML-KEM-768",
    "AES-256-GCM",
    "ChaCha20-Poly1305",
    "AES-256-CTR + HMAC-SHA-384",
)
SUITES = {SUITE.suite_id: SUITE}


@dataclass(frozen=True)
class Frame:
    layer: int
    body: bytes

    def encode(self) -> bytes:
        if len(self.body) > MAX_FRAME:
            raise TowerError("frame too large")
        return struct.pack(">B I", self.layer, len(self.body)) + self.body

    @classmethod
    def decode(cls, raw: bytes) -> "Frame":
        if len(raw) < FRAME_HDR:
            raise TowerError("short frame")
        layer, n = struct.unpack(">B I", raw[:FRAME_HDR])
        if n > MAX_FRAME:
            raise TowerError("frame too large")
        if len(raw) != FRAME_HDR + n:
            raise TowerError("bad frame length")
        return cls(layer, raw[FRAME_HDR:])


# ---------------------------------------------------------------------------
# STEP 2/3: nonce, replay window
# ---------------------------------------------------------------------------

def nonce12(epoch: int, seq: int) -> bytes:
    """96-bit nonce. A kulcs layerenként és irányonként külön van."""
    if not 0 <= epoch < 2**32:
        raise TowerError("epoch overflow")
    if not 0 <= seq < 2**64:
        raise TowerError("sequence overflow")
    return struct.pack(">I Q", epoch, seq)


class ReplayWindow:
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


# ---------------------------------------------------------------------------
# STEP 4: header + AAD, amely a transcripthez köt
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Header:
    version: int
    suite: int
    epoch: int
    seq: int
    direction: int
    wire_len: int

    def encode(self) -> bytes:
        return struct.pack(
            ">3s B H I Q B I",
            MAGIC, self.version, self.suite, self.epoch,
            self.seq, self.direction, self.wire_len,
        )

    @classmethod
    def decode(cls, data: bytes) -> tuple["Header", bytes]:
        if len(data) < 23:
            raise TowerError("short outer header")
        magic, version, suite, epoch, seq, direction, wire_len = struct.unpack(
            ">3s B H I Q B I", data[:23]
        )
        if magic != MAGIC or version != VERSION:
            raise TowerError("bad magic/version")
        if wire_len < TAG + 3:
            raise TowerError("short packet")
        if wire_len > MAX_WIRE:
            raise TowerError("wire packet too large")
        if len(data) != 23 + wire_len:
            raise TowerError("bad framing")
        return cls(version, suite, epoch, seq, direction, wire_len), data[23:]

    def aad(self, transcript: bytes, layer: int, n: int) -> bytes:
        # A transcript az egész handshake-hez köti a csomagot.
        return (
            struct.pack(
                ">3s B H I Q B I B I",
                MAGIC, self.version, self.suite, self.epoch,
                self.seq, self.direction, self.wire_len, layer, n,
            )
            + transcript
        )


# ---------------------------------------------------------------------------
# A három réteg
# ---------------------------------------------------------------------------

class AEADLayer:
    """L1 vagy L2: a belső Frame-et AEAD-dal csomagolja."""

    def __init__(self, layer_id: int, inner_id: int, key: bytes, aead_cls):
        self.layer_id = layer_id
        self.inner_id = inner_id
        self.aead = aead_cls(key)

    def seal(self, inner: Frame, header: Header, nonce: bytes, transcript: bytes) -> Frame:
        if inner.layer != self.inner_id:
            raise TowerError("stack order on seal")
        plain = inner.encode()
        n = len(plain)
        ct = self.aead.encrypt(nonce, plain, header.aad(transcript, self.layer_id, n))
        return Frame(self.layer_id, ct)

    def open(self, outer: Frame, header: Header, nonce: bytes, transcript: bytes) -> Frame:
        if outer.layer != self.layer_id:
            raise TowerError("stack order on open")
        if len(outer.body) < TAG + FRAME_HDR:
            raise TowerError("short AEAD frame")
        n = len(outer.body) - TAG
        plain = self.aead.decrypt(
            nonce, outer.body, header.aad(transcript, self.layer_id, n)
        )
        inner = Frame.decode(plain)
        if inner.layer != self.inner_id:
            raise TowerError("inner layer mismatch")
        return inner


class StreamHMACLayer:
    """L3: AES-256-CTR + HMAC-SHA-384, encrypt-then-MAC."""

    def __init__(self, layer_id: int, inner_id: int, enc_key: bytes, mac_key: bytes):
        self.layer_id = layer_id
        self.inner_id = inner_id
        self.enc_key = enc_key
        self.mac_key = mac_key

    def _cipher(self, nonce: bytes) -> Cipher:
        return Cipher(algorithms.AES(self.enc_key), modes.CTR(nonce + b"\0\0\0\0"))

    def seal(self, inner: Frame, header: Header, nonce: bytes, transcript: bytes) -> Frame:
        if inner.layer != self.inner_id:
            raise TowerError("stack order on seal")
        plain = inner.encode()
        e = self._cipher(nonce).encryptor()
        ct = e.update(plain) + e.finalize()
        tag = hmac.new(
            self.mac_key,
            header.aad(transcript, self.layer_id, len(ct)) + ct,
            hashlib.sha384,
        ).digest()[:MAC]
        return Frame(self.layer_id, ct + tag)

    def open(self, outer: Frame, header: Header, nonce: bytes, transcript: bytes) -> Frame:
        if outer.layer != self.layer_id:
            raise TowerError("stack order on open")
        if len(outer.body) < MAC + FRAME_HDR:
            raise TowerError("short L3 frame")
        ct, tag = outer.body[:-MAC], outer.body[-MAC:]
        want = hmac.new(
            self.mac_key,
            header.aad(transcript, self.layer_id, len(ct)) + ct,
            hashlib.sha384,
        ).digest()[:MAC]
        if not hmac.compare_digest(tag, want):
            raise TowerError("L3 MAC failure")
        d = self._cipher(nonce).decryptor()
        plain = d.update(ct) + d.finalize()
        inner = Frame.decode(plain)
        if inner.layer != self.inner_id:
            raise TowerError("inner layer mismatch")
        return inner


class Layer(Protocol):
    layer_id: int
    inner_id: int

    def seal(self, inner: Frame, header: Header, nonce: bytes, transcript: bytes) -> Frame: ...
    def open(self, outer: Frame, header: Header, nonce: bytes, transcript: bytes) -> Frame: ...


class TowerStack:
    """LIFO stack: [L3, L2, L1]. push = seal, pop = open."""

    def __init__(self, layers: list[Layer]):
        if not layers:
            raise TowerError("empty tower")
        for lower, upper in zip(layers, layers[1:]):
            if upper.inner_id != lower.layer_id:
                raise TowerError("layers are not adjacent")
        self.layers = list(layers)

    def push(self, frame: Frame, header: Header, nonce: bytes, transcript: bytes) -> Frame:
        for layer in self.layers:
            frame = layer.seal(frame, header, nonce, transcript)
        return frame

    def pop(
        self,
        frame: Frame,
        header: Header,
        nonce: bytes,
        transcript: bytes,
        after_l1=None,
    ) -> Frame:
        # reversed: L1, L2, L3
        for index, layer in enumerate(reversed(self.layers)):
            frame = layer.open(frame, header, nonce, transcript)
            if index == 0 and after_l1 is not None:
                after_l1(frame)
        return frame


# ---------------------------------------------------------------------------
# STEP 1/4: key schedule
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrafficKeys:
    l1: bytes
    l2: bytes
    l3_enc: bytes
    l3_mac: bytes


@dataclass(frozen=True)
class HandshakeKeys:
    suite: TowerSuite
    master: bytes
    transcript: bytes
    c2s: TrafficKeys
    s2c: TrafficKeys
    c2s_finished: bytes
    s2c_finished: bytes


def expand_label(secret: bytes, label: bytes, context: bytes, n: int) -> bytes:
    full = b"tower-stack/1.5 " + label
    info = (
        struct.pack(">H", n)
        + bytes([len(full)])
        + full
        + bytes([len(context)])
        + context
    )
    return HKDFExpand(hashes.SHA256(), n, info).derive(secret)


def derive_master(shared: bytes, th1: bytes) -> tuple[bytes, bytes, bytes]:
    master = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\0" * 32,
        info=b"tower-stack/1.5 master" + th1,
    ).derive(shared)
    c2s_finished = expand_label(master, b"finished c2s", th1, 32)
    s2c_finished = expand_label(master, b"finished s2c", th1, 32)
    return master, c2s_finished, s2c_finished


def derive_traffic(master: bytes, transcript: bytes, epoch: int) -> tuple[TrafficKeys, TrafficKeys]:
    ctx = transcript + struct.pack(">I", epoch)

    def ks(direction: bytes) -> TrafficKeys:
        return TrafficKeys(
            l1=expand_label(master, direction + b" l1", ctx, 32),
            l2=expand_label(master, direction + b" l2", ctx, 32),
            l3_enc=expand_label(master, direction + b" l3-enc", ctx, 32),
            l3_mac=expand_label(master, direction + b" l3-mac", ctx, 48),
        )

    return ks(b"c2s"), ks(b"s2c")


def make_stack(keys: TrafficKeys) -> TowerStack:
    return TowerStack([
        StreamHMACLayer(3, 0, keys.l3_enc, keys.l3_mac),
        AEADLayer(2, 3, keys.l2, ChaCha20Poly1305),
        AEADLayer(1, 2, keys.l1, AESGCM),
    ])


# ---------------------------------------------------------------------------
# STEP 1: 1-RTT handshake
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClientHello:
    client_random: bytes
    x25519_pub: bytes
    mlkem_pub: bytes
    offers: tuple[int, ...]
    version: int = VERSION

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
class ServerHello:
    server_random: bytes
    x25519_pub: bytes
    mlkem_ct: bytes
    selected_suite: int
    signature: bytes
    version: int = VERSION

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
        return self.prefix() + struct.pack(">H", len(self.signature)) + self.signature


def negotiate(offers: tuple[int, ...], policy: tuple[TowerSuite, ...]) -> TowerSuite:
    allowed = {s.suite_id: s for s in policy}
    for suite_id in offers:
        if suite_id in allowed:
            return allowed[suite_id]
    raise TowerError("no common tower suite")


def make_client_hello(offers: tuple[int, ...]) -> tuple[ClientHello, X25519PrivateKey, mlkem.MLKEM768PrivateKey]:
    x_priv = X25519PrivateKey.generate()
    kem_priv = mlkem.MLKEM768PrivateKey.generate()
    ch = ClientHello(
        client_random=os.urandom(32),
        x25519_pub=x_priv.public_key().public_bytes_raw(),
        mlkem_pub=kem_priv.public_key().public_bytes_raw(),
        offers=tuple(offers),
    )
    return ch, x_priv, kem_priv


def server_accept(
    ch: ClientHello,
    server_sign_key: mldsa.MLDSA65PrivateKey,
    policy: tuple[TowerSuite, ...],
) -> tuple[ServerHello, bytes, HandshakeKeys]:
    """Returns (ServerHello, server Finished MAC, handshake keys)."""
    if ch.version != VERSION:
        raise TowerError("unsupported handshake version")
    suite = negotiate(ch.offers, policy)
    server_x = X25519PrivateKey.generate()
    client_kem_pub = mlkem.MLKEM768PublicKey.from_public_bytes(ch.mlkem_pub)
    mlkem_ss, mlkem_ct = client_kem_pub.encapsulate()

    sh_unsigned = ServerHello(
        server_random=os.urandom(32),
        x25519_pub=server_x.public_key().public_bytes_raw(),
        mlkem_ct=mlkem_ct,
        selected_suite=suite.suite_id,
        signature=b"",
    )
    th1 = hashlib.sha256(ch.encode() + sh_unsigned.prefix()).digest()
    signature = server_sign_key.sign(th1)
    sh = ServerHello(
        server_random=sh_unsigned.server_random,
        x25519_pub=sh_unsigned.x25519_pub,
        mlkem_ct=sh_unsigned.mlkem_ct,
        selected_suite=sh_unsigned.selected_suite,
        signature=signature,
    )

    x_ss = server_x.exchange(X25519PublicKey.from_public_bytes(ch.x25519_pub))
    shared = x_ss + mlkem_ss  # production: standard hybrid combiner
    master, c2s_finished, s2c_finished = derive_master(shared, th1)
    server_finished = hmac.new(
        s2c_finished, b"tower finished" + bytes([1]) + th1, hashlib.sha256
    ).digest()
    th2 = hashlib.sha256(th1 + server_finished).digest()
    c2s, s2c = derive_traffic(master, th2, 0)
    hk = HandshakeKeys(suite, master, th2, c2s, s2c, c2s_finished, s2c_finished)
    return sh, server_finished, hk


def client_accept(
    ch: ClientHello,
    ch_x: X25519PrivateKey,
    ch_kem: mlkem.MLKEM768PrivateKey,
    sh: ServerHello,
    server_verify_key: mldsa.MLDSA65PublicKey,
    server_finished: bytes,
) -> tuple[bytes, HandshakeKeys]:
    """Returns (client Finished MAC, handshake keys)."""
    if sh.version != VERSION:
        raise TowerError("unsupported handshake version")
    if sh.selected_suite not in ch.offers:
        raise TowerError("server selected an unoffered suite")
    suite = SUITES.get(sh.selected_suite)
    if suite is None:
        raise TowerError("unknown suite")

    th1 = hashlib.sha256(ch.encode() + sh.prefix()).digest()
    try:
        server_verify_key.verify(sh.signature, th1)
    except Exception:
        raise TowerError("server authentication failed") from None

    x_ss = ch_x.exchange(X25519PublicKey.from_public_bytes(sh.x25519_pub))
    mlkem_ss = ch_kem.decapsulate(sh.mlkem_ct)
    shared = x_ss + mlkem_ss  # production: standard hybrid combiner
    master, c2s_finished, s2c_finished = derive_master(shared, th1)

    want_server = hmac.new(
        s2c_finished, b"tower finished" + bytes([1]) + th1, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(want_server, server_finished):
        raise TowerError("server Finished failed")

    th2 = hashlib.sha256(th1 + server_finished).digest()
    c2s, s2c = derive_traffic(master, th2, 0)
    hk = HandshakeKeys(suite, master, th2, c2s, s2c, c2s_finished, s2c_finished)

    client_finished = hmac.new(
        c2s_finished, b"tower finished" + bytes([0]) + th2, hashlib.sha256
    ).digest()
    return client_finished, hk


def server_verify_client_finished(hk: HandshakeKeys, client_finished: bytes) -> None:
    want = hmac.new(
        hk.c2s_finished,
        b"tower finished" + bytes([0]) + hk.transcript,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(want, client_finished):
        raise TowerError("client Finished failed")


# ---------------------------------------------------------------------------
# STEP 2/3/5: session, nonce/epoch, replay, padding, uniform errors
# ---------------------------------------------------------------------------

def pad(pt: bytes) -> bytes:
    n = PAD - (len(pt) % PAD)
    return pt + bytes([n]) * n


def unpad(padded: bytes) -> bytes:
    if not padded:
        raise TowerError("empty padding")
    n = padded[-1]
    if n < 1 or n > PAD or n > len(padded) or padded[-n:] != bytes([n]) * n:
        raise TowerError("bad padding")
    return padded[:-n]


class TowerSession:
    def __init__(self, hk: HandshakeKeys, role: int):
        if role not in (0, 1):
            raise TowerError("bad role")
        self.role = role                    # 0 = client, 1 = server
        self.send_direction = role          # client -> server = 0
        self.recv_direction = 1 - role      # server -> client = 1
        self.suite = hk.suite
        self.master = hk.master
        self.transcript = hk.transcript
        self.epoch = 0
        self.c2s = hk.c2s
        self.s2c = hk.s2c
        self.stacks = {
            0: make_stack(self.c2s),
            1: make_stack(self.s2c),
        }
        self.send_seq = {0: 0, 1: 0}
        self.replay = {0: ReplayWindow(), 1: ReplayWindow()}

    def seal(self, plaintext: bytes) -> bytes:
        direction = self.send_direction
        if len(plaintext) > MAX_PLAINTEXT:
            raise TowerError("fragment first")
        if self.send_seq[direction] >= MAX_SEQ:
            raise TowerError("rekey required")

        seq = self.send_seq[direction]
        self.send_seq[direction] += 1
        padded = pad(plaintext)
        p = len(padded)
        # 3 frame headers (L3, L2, L1-body), MAC, and two AEAD tags.
        wire_len = p + 3 * FRAME_HDR + MAC + 2 * TAG
        header = Header(VERSION, self.suite.suite_id, self.epoch, seq, direction, wire_len)
        nonce = nonce12(self.epoch, seq)
        frame = self.stacks[direction].push(
            Frame(0, padded), header, nonce, self.transcript
        )
        if frame.layer != 1 or len(frame.body) != wire_len:
            raise TowerError("internal wire length mismatch")
        return header.encode() + frame.body

    def open(self, packet: bytes) -> bytes:
        try:
            header, l1_body = Header.decode(packet)
            if header.suite != self.suite.suite_id:
                raise TowerError("unsupported suite")
            if header.direction != self.recv_direction:
                raise TowerError("wrong direction")
            if header.epoch != self.epoch:
                raise TowerError("wrong epoch")
            if len(l1_body) != header.wire_len:
                raise TowerError("wire length mismatch")

            nonce = nonce12(header.epoch, header.seq)
            frame = Frame(1, l1_body)
            frame = self.stacks[header.direction].pop(
                frame,
                header,
                nonce,
                self.transcript,
                after_l1=lambda _: self.replay[header.direction].check_and_update(header.seq),
            )
            if frame.layer != 0:
                raise TowerError("top of stack is not plaintext")
            return unpad(frame.body)
        except Exception:
            # Single external error; log details internally if needed.
            raise TowerError("decrypt failed") from None

    def rekey(self) -> None:
        """Both peers must call this; production needs an authenticated KeyUpdate."""
        if self.epoch >= 2**32 - 1:
            raise TowerError("epoch exhausted")
        self.epoch += 1
        self.c2s, self.s2c = derive_traffic(self.master, self.transcript, self.epoch)
        self.stacks = {0: make_stack(self.c2s), 1: make_stack(self.s2c)}
        self.send_seq = {0: 0, 1: 0}
        self.replay = {0: ReplayWindow(), 1: ReplayWindow()}


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo() -> None:
    # Server trust anchor: a client already knows this ML-DSA-65 public key.
    server_sign = mldsa.MLDSA65PrivateKey.generate()
    server_verify = server_sign.public_key()

    ch, ch_x, ch_kem = make_client_hello((SUITE.suite_id,))
    sh, server_finished, server_hk = server_accept(ch, server_sign, (SUITE,))
    client_finished, client_hk = client_accept(
        ch, ch_x, ch_kem, sh, server_verify, server_finished
    )
    server_verify_client_finished(server_hk, client_finished)

    client = TowerSession(client_hk, role=0)
    server = TowerSession(server_hk, role=1)

    wire = client.seal(b"hello through the tower")
    assert server.open(wire) == b"hello through the tower"

    # Reflection: the client must not accept its own c2s packet.
    try:
        client.open(wire)
    except TowerError:
        print("reflection rejected")
    else:
        raise AssertionError("reflected packet accepted")

    reply = server.seal(b"reply")
    assert client.open(reply) == b"reply"

    # Tamper: L1 must reject it.
    bad = bytearray(client.seal(b"tamper me"))
    bad[-1] ^= 1
    try:
        server.open(bytes(bad))
    except TowerError as e:
        print("tamper rejected:", e)
    else:
        raise AssertionError("tampered packet accepted")

    # Replay: same packet twice must fail.
    replay = client.seal(b"replay me")
    assert server.open(replay) == b"replay me"
    try:
        server.open(replay)
    except TowerError as e:
        print("replay rejected:", e)
    else:
        raise AssertionError("replayed packet accepted")

    # Rekey: both sides derive epoch 1, old sequence space is not reused.
    client.rekey()
    server.rekey()
    after = client.seal(b"after rekey")
    assert server.open(after) == b"after rekey"

    # Old epoch must not be accepted after rekey.
    try:
        server.open(wire)
    except TowerError:
        print("old epoch rejected")
    else:
        raise AssertionError("old epoch accepted")

    print("ok: handshake + record layer + replay + rekey")
    print("wire bytes:", len(wire))


if __name__ == "__main__":
    demo()

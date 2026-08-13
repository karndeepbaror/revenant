"""
REVENANT :: tls_analysis.py
================================================================
TLS investigation module.

Parses the raw bytes of a TLS ClientHello handshake message by
hand (no decryption — TLS metadata is sent in plaintext before
encryption begins, which is exactly why this technique works
on encrypted traffic without ever breaking the encryption).

For every ClientHello observed, REVENANT extracts:
  - SNI (Server Name Indication) — which hostname the client is
    actually asking for, even over plain IP:443 with no DNS
    lookup logged.
  - A JA3-style fingerprint — an md5 hash of
    (TLS version, cipher suites, extensions, elliptic curves,
    EC point formats), which is a well-established technique
    for fingerprinting the *client application/library* making
    the connection (a specific malware family's TLS stack often
    produces a distinctive, stable JA3 hash regardless of which
    domain it connects to).
================================================================
"""

from __future__ import annotations
import struct
import hashlib
from dataclasses import dataclass, field
from collections import Counter


@dataclass
class TLSClientHello:
    frame_index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    tls_version: str
    sni: str = ""
    cipher_suites: list = field(default_factory=list)
    extensions: list = field(default_factory=list)
    ja3_string: str = ""
    ja3_hash: str = ""


@dataclass
class TLSAnalysisResult:
    client_hellos: list = field(default_factory=list)
    unique_sni_count: int = 0
    top_sni: list = field(default_factory=list)
    unique_ja3_hashes: list = field(default_factory=list)      # [(hash, count, example_sni)]
    ja3_reused_across_hosts: list = field(default_factory=list)  # same JA3 hitting many distinct dst IPs
    connections_without_sni: int = 0


TLS_VERSION_MAP = {
    0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}


def _parse_client_hello(payload: bytes):
    """Hand-rolled TLS record + handshake + extension parser for ClientHello only."""
    try:
        if len(payload) < 6 or payload[0] != 0x16:  # 0x16 = Handshake record
            return None
        record_version = struct.unpack(">H", payload[1:3])[0]
        handshake_type = payload[5]
        if handshake_type != 0x01:  # 0x01 = ClientHello
            return None

        pos = 9  # skip record header(5) + handshake header(4)
        client_version = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        pos += 32  # random

        session_id_len = payload[pos]
        pos += 1 + session_id_len

        cipher_suites_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            cs = struct.unpack(">H", payload[pos + i:pos + i + 2])[0]
            cipher_suites.append(cs)
        pos += cipher_suites_len

        comp_len = payload[pos]
        pos += 1 + comp_len

        sni = ""
        extensions = []
        ec_curves = []
        ec_point_formats = []

        if pos + 2 <= len(payload):
            ext_total_len = struct.unpack(">H", payload[pos:pos + 2])[0]
            pos += 2
            ext_end = pos + ext_total_len

            while pos + 4 <= ext_end and pos + 4 <= len(payload):
                ext_type = struct.unpack(">H", payload[pos:pos + 2])[0]
                ext_len = struct.unpack(">H", payload[pos + 2:pos + 4])[0]
                ext_data = payload[pos + 4: pos + 4 + ext_len]
                extensions.append(ext_type)

                if ext_type == 0x0000 and len(ext_data) > 5:  # server_name
                    try:
                        name_len = struct.unpack(">H", ext_data[3:5])[0]
                        sni = ext_data[5:5 + name_len].decode(errors="ignore")
                    except Exception:
                        pass
                elif ext_type == 0x000a:  # supported_groups (elliptic curves)
                    try:
                        n = struct.unpack(">H", ext_data[0:2])[0]
                        for i in range(0, n, 2):
                            ec_curves.append(struct.unpack(">H", ext_data[2 + i:4 + i])[0])
                    except Exception:
                        pass
                elif ext_type == 0x000b:  # ec_point_formats
                    try:
                        n = ext_data[0]
                        ec_point_formats = list(ext_data[1:1 + n])
                    except Exception:
                        pass

                pos += 4 + ext_len

        return {
            "client_version": client_version,
            "cipher_suites": cipher_suites,
            "extensions": extensions,
            "ec_curves": ec_curves,
            "ec_point_formats": ec_point_formats,
            "sni": sni,
        }
    except Exception:
        return None


def _grease(val: int) -> bool:
    # GREASE values (RFC 8701) are placeholders that must be excluded from JA3
    return (val & 0x0F0F) == 0x0A0A


def _build_ja3(parsed: dict) -> tuple:
    version = parsed["client_version"]
    ciphers = "-".join(str(c) for c in parsed["cipher_suites"] if not _grease(c))
    exts = "-".join(str(e) for e in parsed["extensions"] if not _grease(e))
    curves = "-".join(str(c) for c in parsed["ec_curves"] if not _grease(c))
    points = "-".join(str(p) for p in parsed["ec_point_formats"])
    ja3_string = f"{version},{ciphers},{exts},{curves},{points}"
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
    return ja3_string, ja3_hash


def analyze_tls(frames) -> TLSAnalysisResult:
    result = TLSAnalysisResult()
    sni_counter = Counter()
    ja3_counter = Counter()
    ja3_example_sni = {}
    ja3_dst_ips = {}

    for f in frames:
        if f.proto != "TCP" or not f.payload:
            continue
        if f.dst_port not in (443, 8443, 465, 993, 995) and f.src_port not in (443, 8443, 465, 993, 995):
            if len(f.payload) < 6 or f.payload[0] != 0x16:
                continue

        parsed = _parse_client_hello(f.payload)
        if not parsed:
            continue

        ja3_string, ja3_hash = _build_ja3(parsed)
        hello = TLSClientHello(
            frame_index=f.index, timestamp=f.timestamp, src_ip=f.src_ip or "",
            dst_ip=f.dst_ip or "", dst_port=f.dst_port or 0,
            tls_version=TLS_VERSION_MAP.get(parsed["client_version"], hex(parsed["client_version"])),
            sni=parsed["sni"], cipher_suites=parsed["cipher_suites"],
            extensions=parsed["extensions"], ja3_string=ja3_string, ja3_hash=ja3_hash,
        )
        result.client_hellos.append(hello)

        if hello.sni:
            sni_counter[hello.sni] += 1
        else:
            result.connections_without_sni += 1

        ja3_counter[ja3_hash] += 1
        if ja3_hash not in ja3_example_sni and hello.sni:
            ja3_example_sni[ja3_hash] = hello.sni
        ja3_dst_ips.setdefault(ja3_hash, set()).add(hello.dst_ip)

    result.unique_sni_count = len(sni_counter)
    result.top_sni = sni_counter.most_common(15)
    result.unique_ja3_hashes = [
        (h, cnt, ja3_example_sni.get(h, "")) for h, cnt in ja3_counter.most_common(15)
    ]
    result.ja3_reused_across_hosts = [
        {"ja3_hash": h, "distinct_dst_ips": len(ips), "example_sni": ja3_example_sni.get(h, "")}
        for h, ips in ja3_dst_ips.items() if len(ips) >= 3
    ]

    return result

"""
REVENANT :: pcap_loader.py
================================================================
Evidence ingestion layer.

Loads a .pcap / .pcapng file via scapy, then walks every frame
exactly once and normalizes it into a lightweight `Frame` record
containing only the fields every downstream module needs. This
single-pass normalization means every analysis module below
operates on cheap, flat Python objects instead of re-parsing
raw scapy layers over and over — critical once a capture grows
into the tens of thousands of packets.
================================================================
"""

from __future__ import annotations
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from scapy.all import rdpcap, PcapReader
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw


@dataclass
class Frame:
    index: int
    timestamp: float
    length: int

    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None

    ip_version: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None

    proto: str = "OTHER"          # TCP / UDP / ICMP / ARP / OTHER
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    tcp_flags: Optional[str] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_window: Optional[int] = None

    payload: bytes = b""
    payload_len: int = 0

    is_dns: bool = False
    is_arp: bool = False

    dns_qname: str = ""
    dns_qtype: str = ""
    dns_is_response: bool = False
    dns_rcode: int = 0
    dns_response_ips: list = field(default_factory=list)

    arp_op: Optional[int] = None
    arp_hwsrc: Optional[str] = None
    arp_hwdst: Optional[str] = None

    raw_summary: str = ""


@dataclass
class CaptureMeta:
    filepath: str = ""
    file_size_bytes: int = 0
    packet_count: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    duration_seconds: float = 0.0
    link_type_note: str = "Ethernet (assumed)"
    load_seconds: float = 0.0
    truncated: bool = False
    truncation_limit: Optional[int] = None


TCP_FLAG_MAP = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}

DNS_QTYPE_MAP = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
                  16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def _decode_tcp_flags(flags) -> str:
    try:
        s = str(flags)
    except Exception:
        return ""
    parts = [TCP_FLAG_MAP.get(ch, ch) for ch in s if ch in TCP_FLAG_MAP]
    return ",".join(parts) if parts else s


def load_capture(filepath: str, packet_limit: Optional[int] = None, progress_cb=None) -> tuple[list[Frame], CaptureMeta]:
    """
    Stream-load a pcap/pcapng file and return (frames, meta).
    Uses PcapReader (streaming) rather than rdpcap (loads everything
    into memory at once) so very large captures don't blow up RAM.
    """
    meta = CaptureMeta()
    meta.filepath = os.path.abspath(filepath)
    meta.file_size_bytes = os.path.getsize(filepath)
    meta.truncation_limit = packet_limit

    frames: list[Frame] = []
    start = time.time()

    with PcapReader(filepath) as reader:
        for idx, pkt in enumerate(reader):
            if packet_limit and idx >= packet_limit:
                meta.truncated = True
                break

            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
            frame = Frame(index=idx, timestamp=ts, length=len(pkt))

            if Ether in pkt:
                frame.eth_src = pkt[Ether].src
                frame.eth_dst = pkt[Ether].dst

            if ARP in pkt:
                frame.is_arp = True
                frame.proto = "ARP"
                frame.src_ip = pkt[ARP].psrc
                frame.dst_ip = pkt[ARP].pdst
                frame.arp_op = int(pkt[ARP].op)
                frame.arp_hwsrc = pkt[ARP].hwsrc
                frame.arp_hwdst = pkt[ARP].hwdst

            if IP in pkt:
                frame.ip_version = 4
                frame.src_ip = pkt[IP].src
                frame.dst_ip = pkt[IP].dst
                frame.ttl = pkt[IP].ttl
            elif IPv6 in pkt:
                frame.ip_version = 6
                frame.src_ip = pkt[IPv6].src
                frame.dst_ip = pkt[IPv6].dst
                frame.ttl = getattr(pkt[IPv6], "hlim", None)

            if TCP in pkt:
                frame.proto = "TCP"
                frame.src_port = int(pkt[TCP].sport)
                frame.dst_port = int(pkt[TCP].dport)
                frame.tcp_flags = _decode_tcp_flags(pkt[TCP].flags)
                frame.tcp_seq = int(pkt[TCP].seq)
                frame.tcp_ack = int(pkt[TCP].ack)
                frame.tcp_window = int(pkt[TCP].window)
            elif UDP in pkt:
                frame.proto = "UDP"
                frame.src_port = int(pkt[UDP].sport)
                frame.dst_port = int(pkt[UDP].dport)
            elif ICMP in pkt:
                frame.proto = "ICMP"

            if DNS in pkt:
                frame.is_dns = True
                dns = pkt[DNS]
                try:
                    frame.dns_is_response = bool(dns.qr == 1)
                    frame.dns_rcode = int(dns.rcode) if dns.rcode is not None else 0
                    if dns.qdcount and dns.qd is not None:
                        qname_raw = dns.qd.qname
                        frame.dns_qname = (qname_raw.decode(errors="ignore") if isinstance(qname_raw, bytes) else str(qname_raw)).rstrip(".")
                        frame.dns_qtype = DNS_QTYPE_MAP.get(int(dns.qd.qtype), str(dns.qd.qtype))
                    if frame.dns_is_response and dns.ancount:
                        an = dns.an
                        for _ in range(dns.ancount):
                            if an is None:
                                break
                            rdata = getattr(an, "rdata", None)
                            if rdata is not None:
                                val = rdata.decode(errors="ignore") if isinstance(rdata, bytes) else str(rdata)
                                frame.dns_response_ips.append(val)
                            an = an.payload if hasattr(an, "payload") and isinstance(an.payload, DNSRR) else None
                except Exception:
                    pass

            if Raw in pkt:
                try:
                    frame.payload = bytes(pkt[Raw].load)
                    frame.payload_len = len(frame.payload)
                except Exception:
                    pass

            try:
                frame.raw_summary = pkt.summary()
            except Exception:
                frame.raw_summary = ""

            frames.append(frame)

            if progress_cb and idx % 500 == 0:
                progress_cb(idx)

    meta.packet_count = len(frames)
    if frames:
        meta.first_ts = frames[0].timestamp
        meta.last_ts = frames[-1].timestamp
        meta.duration_seconds = max(0.0, meta.last_ts - meta.first_ts)
    meta.load_seconds = time.time() - start

    return frames, meta

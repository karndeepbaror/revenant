"""
REVENANT :: dns_analysis.py
================================================================
DNS investigation module.

Extracts every DNS query/response observed in the capture, then
applies two well-established detection heuristics on top:

  1. DGA-style domain scoring — Domain Generation Algorithm
     malware families produce domains that are lexically
     "random" (high character entropy, unusual consonant runs,
     abnormal digit ratio). We score every queried domain on
     these axes rather than relying on any external blocklist.

  2. DNS tunneling indicators — abnormally long labels/queries,
     high query-volume against a single suffix in a short
     window, and unusually large TXT/NULL responses are the
     classic fingerprints of data being smuggled through DNS.
================================================================
"""

from __future__ import annotations
import math
import re
from dataclasses import dataclass, field
from collections import Counter, defaultdict

VOWELS = set("aeiou")


@dataclass
class DNSQuery:
    frame_index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    query_name: str
    qtype: str
    is_response: bool
    response_ips: list = field(default_factory=list)
    dga_score: float = 0.0
    dga_flag: bool = False
    tunneling_flag: bool = False
    query_length: int = 0


@dataclass
class DNSAnalysisResult:
    total_queries: int = 0
    unique_domains: int = 0
    queries: list = field(default_factory=list)
    top_domains: list = field(default_factory=list)
    top_queriers: list = field(default_factory=list)
    suspected_dga_domains: list = field(default_factory=list)
    suspected_tunneling: list = field(default_factory=list)
    qtype_distribution: dict = field(default_factory=dict)
    nxdomain_count: int = 0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _dga_score(domain: str) -> float:
    """
    Heuristic 0-100 'looks algorithmically generated' score based on:
      - character entropy of the registrable label
      - consonant-run length (real words rarely stack 5+ consonants)
      - digit ratio
      - vowel ratio (very low vowel ratio is unusual for real words)
    A heuristic signal meant to focus human attention — not a verdict.
    """
    label = domain.split(".")[0].lower()
    label = re.sub(r"[^a-z0-9]", "", label)
    if len(label) < 6:
        return 0.0

    entropy = _shannon_entropy(label)
    entropy_score = min(entropy / 4.0, 1.0) * 40

    max_consonant_run, run = 0, 0
    for ch in label:
        if ch.isalpha() and ch not in VOWELS:
            run += 1
            max_consonant_run = max(max_consonant_run, run)
        else:
            run = 0
    consonant_score = min(max_consonant_run / 6.0, 1.0) * 25

    digit_ratio = sum(1 for c in label if c.isdigit()) / len(label)
    digit_score = min(digit_ratio / 0.4, 1.0) * 15

    vowel_ratio = sum(1 for c in label if c in VOWELS) / len(label)
    low_vowel_score = (1.0 - min(vowel_ratio / 0.25, 1.0)) * 20

    return round(min(100.0, entropy_score + consonant_score + digit_score + low_vowel_score), 2)


def analyze_dns(frames) -> DNSAnalysisResult:
    result = DNSAnalysisResult()
    domain_counter = Counter()
    querier_counter = Counter()
    qtype_counter = Counter()
    suffix_query_times = defaultdict(list)

    for f in frames:
        if not f.is_dns or not f.dns_qname:
            continue

        q = DNSQuery(
            frame_index=f.index, timestamp=f.timestamp, src_ip=f.src_ip or "unknown",
            dst_ip=f.dst_ip or "unknown", query_name=f.dns_qname, qtype=f.dns_qtype,
            is_response=f.dns_is_response, response_ips=list(f.dns_response_ips),
            query_length=len(f.dns_qname),
        )

        if f.dns_rcode == 3:
            result.nxdomain_count += 1

        score = _dga_score(f.dns_qname)
        q.dga_score = score
        q.dga_flag = score >= 55.0

        if len(f.dns_qname) > 60 or f.dns_qtype in ("TXT", "NULL"):
            q.tunneling_flag = True

        domain_counter[f.dns_qname] += 1
        qtype_counter[f.dns_qtype] += 1
        if not f.dns_is_response:
            querier_counter[f.src_ip] += 1

        suffix = ".".join(f.dns_qname.split(".")[-2:]) if "." in f.dns_qname else f.dns_qname
        suffix_query_times[suffix].append(f.timestamp)

        result.queries.append(q)

    result.total_queries = len(result.queries)
    result.unique_domains = len(domain_counter)
    result.top_domains = domain_counter.most_common(15)
    result.top_queriers = querier_counter.most_common(10)
    result.qtype_distribution = dict(qtype_counter)

    seen_dga = {}
    for q in result.queries:
        if q.dga_flag and q.query_name not in seen_dga:
            seen_dga[q.query_name] = q
    result.suspected_dga_domains = sorted(seen_dga.values(), key=lambda x: x.dga_score, reverse=True)[:20]

    seen_tunnel = {}
    for suffix, times in suffix_query_times.items():
        if len(times) >= 20:
            span = max(times) - min(times) if len(times) > 1 else 1
            rate = len(times) / max(span, 1)
            if rate > 0.5:
                seen_tunnel[suffix] = {"suffix": suffix, "query_count": len(times), "rate_per_sec": round(rate, 2),
                                        "reason": "sustained high-frequency queries against one suffix"}
    for q in result.queries:
        if q.tunneling_flag and q.query_name not in seen_tunnel:
            seen_tunnel[q.query_name] = {"suffix": q.query_name, "query_count": 1, "rate_per_sec": 0,
                                          "reason": "abnormally long label or TXT/NULL record"}
    result.suspected_tunneling = list(seen_tunnel.values())[:20]

    return result

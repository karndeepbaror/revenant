"""
REVENANT :: http_analysis.py
================================================================
HTTP investigation module.

Operates entirely on the raw TCP payload bytes REVENANT already
captured per-frame — no re-parsing of the pcap is needed. Two
things happen here:

  1. Request/response line parsing — regex-based extraction of
     Method, Host, URI, User-Agent, and status codes directly
     from cleartext HTTP payloads (the same approach tools like
     NetworkMiner and Zeek's http.log use for plaintext HTTP).

  2. Basic object carving — when a response contains a
     Content-Type/Content-Disposition header followed by a
     body, REVENANT extracts and hashes that body so a
     downloaded file can be identified without ever needing to
     reassemble full TCP streams byte-perfectly.
================================================================
"""

from __future__ import annotations
import re
import hashlib
from dataclasses import dataclass, field
from collections import Counter

REQUEST_LINE_RE = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\S+) HTTP/1\.[01]", re.MULTILINE)
STATUS_LINE_RE = re.compile(rb"^HTTP/1\.[01] (\d{3}) (.*?)\r?$", re.MULTILINE)
HEADER_RE = re.compile(rb"^([A-Za-z0-9\-]+):\s*(.*?)\r?$", re.MULTILINE)


@dataclass
class HTTPRequest:
    frame_index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    method: str
    uri: str
    host: str = ""
    user_agent: str = ""
    referer: str = ""
    is_suspicious_ua: bool = False


@dataclass
class HTTPResponse:
    frame_index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    status_code: int
    content_type: str = ""
    content_length: int = 0
    server: str = ""


@dataclass
class CarvedObject:
    frame_index: int
    content_type: str
    size_bytes: int
    sha256: str
    filename_guess: str = ""


@dataclass
class HTTPAnalysisResult:
    requests: list = field(default_factory=list)
    responses: list = field(default_factory=list)
    carved_objects: list = field(default_factory=list)
    top_hosts: list = field(default_factory=list)
    top_uris: list = field(default_factory=list)
    method_distribution: dict = field(default_factory=dict)
    status_distribution: dict = field(default_factory=dict)
    suspicious_user_agents: list = field(default_factory=list)
    plaintext_credentials_found: list = field(default_factory=list)


COMMON_BROWSER_TOKENS = ("Mozilla", "Chrome", "Safari", "Firefox", "Edg", "OPR", "AppleWebKit")


def _headers_dict(block: bytes) -> dict:
    headers = {}
    for m in HEADER_RE.finditer(block):
        k = m.group(1).decode(errors="ignore").strip().lower()
        v = m.group(2).decode(errors="ignore").strip()
        headers[k] = v
    return headers


def _looks_like_credentials(payload: bytes) -> list:
    hits = []
    text = payload.decode(errors="ignore")
    for pattern, label in [
        (r"(?i)\b(username|user|login|email)=([^&\s]{2,60})", "username field"),
        (r"(?i)\b(password|passwd|pwd)=([^&\s]{2,60})", "password field"),
        (r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{6,}", "HTTP Basic Auth header"),
    ]:
        if re.search(pattern, text):
            hits.append(label)
    return hits


def analyze_http(frames) -> HTTPAnalysisResult:
    result = HTTPAnalysisResult()
    host_counter = Counter()
    uri_counter = Counter()
    method_counter = Counter()
    status_counter = Counter()
    seen_ua = set()

    for f in frames:
        if f.proto != "TCP" or not f.payload:
            continue

        req_match = REQUEST_LINE_RE.match(f.payload)
        if req_match:
            headers = _headers_dict(f.payload)
            method = req_match.group(1).decode()
            uri = req_match.group(2).decode(errors="ignore")
            host = headers.get("host", "")
            ua = headers.get("user-agent", "")

            is_susp = False
            if ua:
                if not any(tok in ua for tok in COMMON_BROWSER_TOKENS):
                    is_susp = True
                    if ua not in seen_ua:
                        result.suspicious_user_agents.append(ua)
                        seen_ua.add(ua)

            req = HTTPRequest(
                frame_index=f.index, timestamp=f.timestamp, src_ip=f.src_ip or "",
                dst_ip=f.dst_ip or "", dst_port=f.dst_port or 0,
                method=method, uri=uri, host=host, user_agent=ua,
                referer=headers.get("referer", ""), is_suspicious_ua=is_susp,
            )
            result.requests.append(req)
            method_counter[method] += 1
            if host:
                host_counter[host] += 1
                uri_counter[f"{host}{uri}"[:80]] += 1
            else:
                uri_counter[uri[:80]] += 1

            creds = _looks_like_credentials(f.payload)
            if creds:
                result.plaintext_credentials_found.append({
                    "frame_index": f.index, "src_ip": f.src_ip, "dst_ip": f.dst_ip,
                    "indicators": creds,
                })
            continue

        status_match = STATUS_LINE_RE.match(f.payload)
        if status_match:
            headers = _headers_dict(f.payload)
            code = int(status_match.group(1))
            resp = HTTPResponse(
                frame_index=f.index, timestamp=f.timestamp, src_ip=f.src_ip or "",
                dst_ip=f.dst_ip or "", status_code=code,
                content_type=headers.get("content-type", ""),
                content_length=int(headers.get("content-length", 0) or 0),
                server=headers.get("server", ""),
            )
            result.responses.append(resp)
            status_counter[code] += 1

            body_start = f.payload.find(b"\r\n\r\n")
            if body_start != -1 and resp.content_type and not resp.content_type.startswith("text/html"):
                body = f.payload[body_start + 4:]
                if len(body) >= 16:
                    digest = hashlib.sha256(body).hexdigest()
                    fname_guess = ""
                    cd = headers.get("content-disposition", "")
                    fm = re.search(r'filename="?([^";]+)"?', cd)
                    if fm:
                        fname_guess = fm.group(1)
                    result.carved_objects.append(CarvedObject(
                        frame_index=f.index, content_type=resp.content_type,
                        size_bytes=len(body), sha256=digest, filename_guess=fname_guess,
                    ))

    result.top_hosts = host_counter.most_common(15)
    result.top_uris = uri_counter.most_common(15)
    result.method_distribution = dict(method_counter)
    result.status_distribution = {str(k): v for k, v in status_counter.items()}

    return result

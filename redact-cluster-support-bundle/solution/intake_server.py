#!/usr/bin/env python3
"""Sluice support-bundle intake. Stdlib only."""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import ipaddress
import json
import re
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICE = "sluice-intake"
VERSION = "5.0.0"

CLUSTER_RANGES = [
    ipaddress.ip_network("10.21.0.0/16"),
    ipaddress.ip_network("10.44.0.0/16"),
    ipaddress.ip_network("10.128.0.0/14"),
    ipaddress.ip_network("172.30.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]
CLUSTER_DNS_SUFFIXES = [".mesa.internal", ".svc.cluster.local", ".cluster.local"]
SECRET_ENV_HINTS = ["PASS", "SECRET", "TOKEN", "CRED", "AUTH", "KEY"]

SALT = b"sluice-intake-redaction-v5"

_SUF = "|".join(re.escape(s) for s in CLUSTER_DNS_SUFFIXES)
# DNS names compare case-insensitively, so the match and the placeholder key do too.
RE_INTERNAL_HOST = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9._-]*(?:%s)\b" % _SUF, re.IGNORECASE)
# A dotted quad that is not part of a longer dotted number, optionally written
# as a reverse-DNS name. One pattern, so the octets of a reverse-DNS name are
# never re-read as a forward address.
RE_ADDRESS = re.compile(
    r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(\.in-addr\.arpa\b)?(?!\d|\.\d)", re.IGNORECASE
)
RE_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
RE_SERVICE_ACCOUNT = re.compile(r"\bsystem:serviceaccount:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+")
RE_BEARER = re.compile(r"\b(Bearer\s+)(\S+)")
RE_VAULT = re.compile(r"\bhvs\.[A-Za-z0-9_.\-]+")
RE_B64 = re.compile(r"\beyJ[A-Za-z0-9+/=_-]+")
SECRET_ENV_HINT = re.compile("|".join(re.escape(h) for h in SECRET_ENV_HINTS), re.IGNORECASE)
# File contents carried as a data URL: the header, then the base64 payload.
RE_DATA_URL = re.compile(r"(data:[^,\s\"']*;base64,)([A-Za-z0-9+/]+={0,2})")
GZIP_MAGIC = b"\x1f\x8b"


class Redactor:
    def __init__(self, bundle):
        self.tokens = {}
        self.used = set()
        evidence = bundle.get("evidence") or {}
        cluster = bundle.get("cluster") or {}

        literals = [
            bundle.get("submitted_by"),
            bundle.get("bundle_id"),
            cluster.get("name"),
            cluster.get("infra_id"),
            cluster.get("api_url"),
            cluster.get("mirror_registry"),
            cluster.get("collected_by"),
        ]
        self.node_ips = set()
        prefixes = set()
        for node in evidence.get("nodes") or []:
            name, mac, ip = node.get("name"), node.get("mac"), node.get("internal_ip")
            if isinstance(ip, str) and ip:
                # Addresses go through the address pass only, so every written
                # form of a node address resolves to one placeholder.
                self.node_ips.add(ip)
            literals.append(mac)
            if isinstance(name, str) and name:
                short = name.split(".")[0]
                literals += [name, short]
                prefixes.add(re.sub(r"-\d+$", "", short))

        for res in evidence.get("resources") or []:
            for container in (res.get("spec") or {}).get("containers") or []:
                for var in container.get("env") or []:
                    key, value = var.get("name"), var.get("value")
                    if not isinstance(key, str) or not isinstance(value, str) or not value:
                        continue
                    if SECRET_ENV_HINT.search(key) and not value.startswith("/"):
                        literals.append(value)

        self.literals = sorted({v for v in literals if isinstance(v, str) and v}, key=len, reverse=True)
        self.families = [re.compile(r"\b%s-\d+\b" % re.escape(p)) for p in sorted(prefixes) if p]

    def token(self, value):
        """Salted digest placeholder: stable across processes, one-to-one per response."""
        if value in self.tokens:
            return self.tokens[value]
        digest = hashlib.sha256(SALT + value.encode("utf-8")).hexdigest()[:16].upper()
        candidate = "REDACTED-%s" % digest
        suffix = 1
        while candidate in self.used:
            suffix += 1
            candidate = "REDACTED-%s-%d" % (digest, suffix)
        self.used.add(candidate)
        self.tokens[value] = candidate
        return candidate

    def sensitive_address(self, text):
        try:
            ip = ipaddress.IPv4Address(text)
        except ValueError:
            return False
        return text in self.node_ips or any(ip in net for net in CLUSTER_RANGES)

    def _address(self, match):
        quad, ptr = match.group(1), match.group(2)
        address = ".".join(reversed(quad.split("."))) if ptr else quad
        if not self.sensitive_address(address):
            return match.group(0)
        return self.token(address) + (ptr or "")

    def text(self, value):
        """Sanitize a string, descending into any data-URL payloads it carries."""
        if not isinstance(value, str) or not value:
            return value
        out, cursor = [], 0
        for match in RE_DATA_URL.finditer(value):
            # Text between payloads takes the plain rules; the payload itself is
            # only ever touched through its decoded content.
            out.append(self._plain(value[cursor:match.start()]))
            out.append(match.group(1) + self._payload(match.group(2)))
            cursor = match.end()
        out.append(self._plain(value[cursor:]))
        return "".join(out)

    def _payload(self, payload):
        """Sanitize a base64 payload in place; leave it untouched when it is
        not UTF-8 text or holds nothing sensitive."""
        try:
            raw = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError):
            return payload
        gzipped = raw[:2] == GZIP_MAGIC
        try:
            content = gzip.decompress(raw) if gzipped else raw
            decoded = content.decode("utf-8")
        except (OSError, EOFError, UnicodeDecodeError, zlib.error):
            return payload
        cleaned = self.text(decoded)
        if cleaned == decoded:
            return payload
        data = cleaned.encode("utf-8")
        if gzipped:
            # A fixed mtime keeps the bytes identical from one run to the next.
            data = gzip.compress(data, mtime=0)
        return base64.b64encode(data).decode("ascii")

    def _plain(self, value):
        if not value:
            return value
        value = RE_INTERNAL_HOST.sub(lambda m: self.token(m.group(0).lower()), value)
        for literal in self.literals:
            if literal in value:
                value = value.replace(literal, self.token(literal))
        for pattern in self.families:
            value = pattern.sub(lambda m: self.token(m.group(0)), value)
        value = RE_MAC.sub(lambda m: self.token(m.group(0)), value)
        value = RE_ADDRESS.sub(self._address, value)
        value = RE_VAULT.sub(lambda m: self.token(m.group(0)), value)
        value = RE_B64.sub(lambda m: self.token(m.group(0)), value)
        value = RE_BEARER.sub(lambda m: m.group(1) + self.token(m.group(2)), value)
        value = RE_SERVICE_ACCOUNT.sub(lambda m: self.token(m.group(0)), value)
        return value


def build_case(bundle):
    evidence = bundle.get("evidence") or {}
    red = Redactor(bundle)
    return {
        "items": [
            {
                "resource_id": res.get("resource_id"),
                "kind": res.get("kind"),
                "namespace": res.get("namespace"),
                "name": red.text(res.get("name")),
                "condition": res.get("condition"),
                "node": red.text(res.get("node")),
            }
            for res in evidence.get("resources") or []
        ],
        "events": [
            {
                "event_id": e.get("event_id"),
                "reason": e.get("reason"),
                "namespace": e.get("namespace"),
                "message": red.text(e.get("message")),
            }
            for e in evidence.get("events") or []
        ],
        "log_excerpts": [
            {"source": x.get("source"), "line": red.text(x.get("line"))}
            for x in evidence.get("log_excerpts") or []
        ],
    }


class IntakeHandler(BaseHTTPRequestHandler):
    server_version = "%s/%s" % (SERVICE, VERSION)

    def _send(self, status, payload):
        body = json.dumps(payload, indent=2, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.split("?")[0] != "/intake":
            self._send(404, {"error": "no such route"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            bundle = json.loads(self.rfile.read(length))
            case = build_case(bundle)
        except Exception:
            self._send(400, {"error": "bundle could not be processed"})
            return
        self._send(200, case)

    def log_message(self, fmt, *args):
        return


def main():
    parser = argparse.ArgumentParser(description="Sluice support-bundle intake")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8721)
    args = parser.parse_args()
    httpd = ThreadingHTTPServer((args.host, args.port), IntakeHandler)
    print("%s %s listening on %s:%d" % (SERVICE, VERSION, args.host, args.port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

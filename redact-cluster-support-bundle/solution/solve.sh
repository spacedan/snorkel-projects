#!/usr/bin/env bash
set -euo pipefail

# Oracle solution for redact-cluster-support-bundle.

cd /app

cat > /app/sluice/intake_server.py <<'PYEOF'
#!/usr/bin/env python3
"""Sluice support-bundle intake. Stdlib only."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICE = "sluice-intake"
VERSION = "2.0.0"

MAX_BUNDLE_BYTES = 1048576
MAX_BUNDLE_DEPTH = 64

CONDITION_WEIGHTS = {
    "EtcdMembersDegraded": 2.5,
    "APIServerUnavailable": 2.2,
    "NodeNotReady": 1.6,
    "CrashLoopBackOff": 1.2,
    "FailedMount": 1.0,
    "ImagePullBackOff": 0.8,
    "PodPending": 0.3,
}
DEFAULT_CONDITION_WEIGHT = 0.4
TOTAL_OUTAGE_MULTIPLIER = 1.5
NODE_NOTREADY_WEIGHT = 0.8
SEVERITY_CEILING = 10.0

CLUSTER_RANGES = [
    ipaddress.ip_network("10.21.0.0/16"),
    ipaddress.ip_network("10.44.0.0/16"),
    ipaddress.ip_network("10.128.0.0/14"),
    ipaddress.ip_network("172.30.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]
CLUSTER_DNS_SUFFIXES = [".mesa.internal", ".svc.cluster.local", ".cluster.local"]
UPSTREAM_REGISTRIES = ["quay.io", "registry.redhat.io", "ghcr.io", "docker.io"]

SALT = b"sluice-intake-redaction-v2"

_SUF = "|".join(re.escape(s) for s in CLUSTER_DNS_SUFFIXES)
RE_INTERNAL_HOST = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9._-]*(?:%s)\b" % _SUF)
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
RE_SERVICE_ACCOUNT = re.compile(r"\bsystem:serviceaccount:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+")
RE_DOMAIN_ACCOUNT = re.compile(r"\b[A-Za-z][A-Za-z0-9._-]*\\+[A-Za-z0-9._-]+")
RE_BEARER = re.compile(r"(?i)\b(Bearer\s+)(\S+)")
RE_KEYED_SECRET = re.compile(r"(?i)\b(password|passwd|token|secret|apikey)(\s*[:=]\s*)(\S+)")
RE_USER_CRED = re.compile(r"(?i)(\buser\s+)([^\s:]+:[^\s]+)")
RE_VAULT = re.compile(r"\bhvs\.[A-Za-z0-9_.\-]+")
RE_B64 = re.compile(r"\beyJ[A-Za-z0-9+/=_-]{8,}")
SECRET_ENV_HINT = re.compile(r"(PASS|SECRET|TOKEN|CRED|AUTH|KEY)", re.I)


class Rejected(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


# --------------------------------------------------------------------------
# Parsing and validation
# --------------------------------------------------------------------------


def scan_depth(raw):
    depth = deepest = 0
    in_string = escaped = False
    for ch in raw:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "}]":
            depth -= 1
    return deepest


def _no_constants(token):
    raise ValueError("non-JSON constant %s" % token)


def require(cond, message):
    if not cond:
        raise Rejected(400, message)


def require_str_fields(obj, fields, what):
    require(isinstance(obj, dict), "%s must be an object" % what)
    for field in fields:
        require(isinstance(obj.get(field), str), "%s requires a string %s" % (what, field))


def parse_bundle(raw_bytes):
    if len(raw_bytes) > MAX_BUNDLE_BYTES:
        raise Rejected(413, "bundle exceeds the maximum accepted size")
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise Rejected(400, "bundle is not valid UTF-8")
    if scan_depth(raw) > MAX_BUNDLE_DEPTH:
        raise Rejected(400, "bundle exceeds the maximum accepted nesting depth")
    try:
        bundle = json.loads(raw, parse_constant=_no_constants)
    except ValueError:
        raise Rejected(400, "bundle is not valid JSON")
    validate(bundle)
    return bundle


def validate(bundle):
    require(isinstance(bundle, dict), "bundle must be a JSON object")
    evidence = bundle.get("evidence", {})
    require(isinstance(evidence, dict), "evidence must be an object")
    for key in ("resources", "nodes", "events", "log_excerpts"):
        value = evidence.get(key, [])
        require(isinstance(value, list), "%s must be a list" % key)
        for entry in value:
            require(isinstance(entry, dict), "%s entries must be objects" % key)
    for res in evidence.get("resources", []):
        require_str_fields(res, ("resource_id", "kind", "namespace", "name", "condition"), "a resource")
    for node in evidence.get("nodes", []):
        require_str_fields(node, ("name",), "a node")
    for event in evidence.get("events", []):
        require_str_fields(event, ("event_id", "reason", "namespace", "message"), "an event")
    for excerpt in evidence.get("log_excerpts", []):
        require_str_fields(excerpt, ("source", "line"), "a log excerpt")


def walk(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------


class Redactor:
    def __init__(self, bundle):
        self.tokens = {}
        self.used = set()
        evidence = bundle.get("evidence") or {}
        cluster = bundle.get("cluster") or {}
        nodes = evidence.get("nodes") or []

        self.literals = []
        for value in (
            bundle.get("submitted_by"),
            bundle.get("bundle_id"),
            cluster.get("name"),
            cluster.get("infra_id"),
            cluster.get("api_url"),
            cluster.get("mirror_registry"),
            cluster.get("collected_by"),
        ):
            if isinstance(value, str) and value:
                self.literals.append((value, "ID"))

        self.node_ips = set()
        prefixes = set()
        for node in nodes:
            for field, kind in (("name", "NODE"), ("internal_ip", "ADDR"), ("mac", "MAC")):
                value = node.get(field)
                if isinstance(value, str) and value:
                    self.literals.append((value, kind))
                    if field == "internal_ip":
                        self.node_ips.add(value)
            name = node.get("name")
            if isinstance(name, str) and name:
                short = name.split(".")[0]
                self.literals.append((short, "NODE"))
                prefixes.add(re.sub(r"-\d+$", "", short))

        for node in walk(bundle):
            if not isinstance(node, dict):
                continue
            for var in node.get("env") or []:
                if not isinstance(var, dict):
                    continue
                name, value = var.get("name"), var.get("value")
                if not isinstance(name, str) or not isinstance(value, str) or not value:
                    continue
                if value.startswith("/"):
                    continue
                if SECRET_ENV_HINT.search(name):
                    self.literals.append((value, "SECRET"))

        self.literals.sort(key=lambda pair: len(pair[0]), reverse=True)
        self.families = [re.compile(r"\b%s-\d+\b" % re.escape(p)) for p in sorted(prefixes) if p]

    def token(self, kind, value):
        if value in self.tokens:
            return self.tokens[value]
        digest = hashlib.sha256(SALT + value.encode("utf-8")).hexdigest()[:16].upper()
        candidate = "%s-%s" % (kind, digest)
        suffix = 1
        while candidate in self.used:            # keep the mapping one-to-one
            suffix += 1
            candidate = "%s-%s-%d" % (kind, digest, suffix)
        self.used.add(candidate)
        self.tokens[value] = candidate
        return candidate

    def _ip(self, match):
        value = match.group(0)
        if value in self.node_ips:
            return self.token("ADDR", value)
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return value
        if any(ip in net for net in CLUSTER_RANGES):
            return self.token("ADDR", value)
        return value

    def text(self, value):
        if not isinstance(value, str) or not value:
            return value
        value = RE_INTERNAL_HOST.sub(lambda m: self.token("HOST", m.group(0)), value)
        for literal, kind in self.literals:
            if literal and literal in value:
                value = value.replace(literal, self.token(kind, literal))
        for pattern in self.families:
            value = pattern.sub(lambda m: self.token("NODE", m.group(0)), value)
        value = RE_MAC.sub(lambda m: self.token("MAC", m.group(0)), value)
        value = RE_IPV4.sub(self._ip, value)
        value = RE_VAULT.sub(lambda m: self.token("SECRET", m.group(0)), value)
        value = RE_B64.sub(lambda m: self.token("SECRET", m.group(0)), value)
        value = RE_BEARER.sub(lambda m: m.group(1) + self.token("SECRET", m.group(2)), value)
        value = RE_KEYED_SECRET.sub(
            lambda m: m.group(1) + m.group(2) + self.token("SECRET", m.group(3)), value
        )
        value = RE_USER_CRED.sub(lambda m: m.group(1) + self.token("SECRET", m.group(2)), value)
        value = RE_SERVICE_ACCOUNT.sub(lambda m: self.token("ACCOUNT", m.group(0)), value)
        value = RE_DOMAIN_ACCOUNT.sub(lambda m: self.token("ACCOUNT", m.group(0)), value)
        return value


# --------------------------------------------------------------------------
# Case construction
# --------------------------------------------------------------------------


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def collect_resources(evidence):
    found = {}
    for node in walk(evidence):
        if isinstance(node, dict) and isinstance(node.get("resource_id"), str):
            rid = node["resource_id"]
            current = found.get(rid)
            if current is None:
                found[rid] = node
                continue
            if len(node) > len(current):
                found[rid] = node
            elif len(node) == len(current) and canonical(node) < canonical(current):
                found[rid] = node
    return [found[k] for k in sorted(found)]


def score(resources, nodes):
    total = 0.0
    for res in resources:
        weight = CONDITION_WEIGHTS.get(res.get("condition"), DEFAULT_CONDITION_WEIGHT)
        replicas = res.get("replicas") or {}
        if isinstance(replicas, dict):
            desired, ready = replicas.get("desired", 0), replicas.get("ready", 0)
            if isinstance(desired, int) and isinstance(ready, int) and desired > 0 and ready == 0:
                weight *= TOTAL_OUTAGE_MULTIPLIER
        total += weight
    for node in nodes:
        for cond in node.get("conditions") or []:
            if isinstance(cond, dict) and cond.get("type") == "Ready" and cond.get("status") != "True":
                total += NODE_NOTREADY_WEIGHT
    return round(min(total, SEVERITY_CEILING), 2)


def case_identifier(bundle):
    digest = hashlib.sha256(canonical(bundle.get("evidence") or {}).encode("utf-8")).hexdigest()
    return "SL-%s" % digest[:16]


def build_case(bundle):
    evidence = bundle.get("evidence") or {}
    resources = collect_resources(evidence)
    nodes = evidence.get("nodes") or []
    red = Redactor(bundle)

    items = [
        {
            "resource_id": res["resource_id"],
            "kind": res["kind"],
            "namespace": res["namespace"],
            "name": red.text(res["name"]),
            "condition": res["condition"],
            "node": red.text(res["node"]) if isinstance(res.get("node"), str) else None,
        }
        for res in resources
    ]
    events = [
        {
            "event_id": e["event_id"],
            "reason": e["reason"],
            "namespace": e["namespace"],
            "message": red.text(e["message"]),
        }
        for e in evidence.get("events") or []
    ]
    excerpts = [
        {"source": x["source"], "line": red.text(x["line"])}
        for x in evidence.get("log_excerpts") or []
    ]

    return {
        "case_id": case_identifier(bundle),
        "severity": score(resources, nodes),
        "items": items,
        "events": events,
        "log_excerpts": excerpts,
        "namespaces": sorted({res["namespace"] for res in resources}),
    }


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


class IntakeHandler(BaseHTTPRequestHandler):
    server_version = "%s/%s" % (SERVICE, VERSION)

    def _send(self, status, payload):
        body = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split("?")[0] == "/healthz":
            self._send(200, {"status": "ok", "service": SERVICE, "version": VERSION})
        else:
            self._send(404, {"error": "no such route"})

    def do_POST(self):
        if self.path.split("?")[0] != "/intake":
            self._send(404, {"error": "no such route"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "invalid Content-Length"})
            return
        if length < 0:
            self._send(400, {"error": "invalid Content-Length"})
            return
        if length > MAX_BUNDLE_BYTES:
            self._send(413, {"error": "bundle exceeds the maximum accepted size"})
            return
        body = self.rfile.read(length)
        try:
            self._send(200, build_case(parse_bundle(body)))
        except Rejected as rejected:
            self._send(rejected.status, {"error": rejected.reason})
        except Exception:
            self._send(400, {"error": "bundle could not be processed"})

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
PYEOF

python3 - <<'CHECKEOF'
import importlib.util, json, pathlib
spec = importlib.util.spec_from_file_location("intake", "/app/sluice/intake_server.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
for path in sorted(pathlib.Path("/app/fixtures").glob("*.json")):
    bundle = json.loads(path.read_text())
    case = mod.build_case(bundle)
    assert set(case) == {"case_id", "severity", "items", "events", "log_excerpts", "namespaces"}
    assert case["severity"] != bundle.get("severity_override")
    print("ok %s severity=%s items=%d" % (path.name, case["severity"], len(case["items"])))
CHECKEOF

echo "oracle complete"
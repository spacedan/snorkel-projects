
#!/usr/bin/env python3
"""Sluice support-bundle intake.
 
Platform engineering drops a collected cluster support bundle here and gets back
a case summary that is cleared to leave the enclave and go to the vendor's
support engineers. Runs on the release workstation, stdlib only -- there is no
package mirror on that side.
 
    ./intake_server.py --port 8721
    curl -s --data-binary @/app/fixtures/bundle_ledger_crashloop.json \
         -H 'Content-Type: application/json' \
         http://127.0.0.1:8721/intake
"""
 
from __future__ import annotations
 
import argparse
import ipaddress
import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
 
SERVICE = "sluice-intake"
VERSION = "1.6.2"
 
# Release defaults. Opened up during the 4.14 upgrade push so platform could see
# exactly what the collector picked up, then never closed again.
CONFIG = {
    "echo_bundle": True,
    "redact_cluster_identifiers": False,
}
 
# Address space and naming owned by the cluster estate: node subnets, pod CIDR,
# service CIDR, loopback.
CLUSTER_RANGES = [
    ipaddress.ip_network("10.21.0.0/16"),
    ipaddress.ip_network("10.44.0.0/16"),
    ipaddress.ip_network("10.128.0.0/14"),
    ipaddress.ip_network("172.30.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]
CLUSTER_DNS_SUFFIXES = [".mesa.internal", ".svc.cluster.local", ".cluster.local"]
 
# Registries the vendor publishes from. Images pulled from anywhere else came
# out of the disconnected mirror.
UPSTREAM_REGISTRIES = ["quay.io", "registry.redhat.io", "ghcr.io", "docker.io"]
 
 
def is_cluster_address(addr):
    """True when the address falls inside cluster-owned space."""
    try:
        ip = ipaddress.ip_address(addr)
    except (ValueError, TypeError):
        return False
    return any(ip in net for net in CLUSTER_RANGES)
 
 
def mask(value):
    """Short stand-in for an identifier. Started for the redaction work, never finished."""
    return "REDACTED-%04x" % (hash(value) & 0xFFFF)
 
 
def collect_resources(node, out):
    """Walk a bundle and pull out every resource record."""
    if isinstance(node, dict):
        if "resource_id" in node:
            out.append(node)
        for value in node.values():
            collect_resources(value, out)
    elif isinstance(node, list):
        for item in node:
            collect_resources(item, out)
    return out
 
 
def build_case(bundle):
    evidence = bundle.get("evidence", {})
    resources = collect_resources(evidence, [])
    nodes = evidence.get("nodes", [])
    events = evidence.get("events", [])
    excerpts = evidence.get("log_excerpts", [])
 
    items = []
    namespaces = set()
    images = set()
    endpoints = set()
 
    for res in resources:
        namespaces.add(res.get("namespace"))
        spec = res.get("spec") or {}
        containers = spec.get("containers") or []
        for container in containers:
            images.add(container.get("image"))
            for var in container.get("env") or []:
                endpoints.add(var.get("value"))
        items.append(
            {
                "resource_id": res.get("resource_id"),
                "kind": res.get("kind"),
                "namespace": res.get("namespace"),
                "name": res.get("name"),
                "condition": res.get("condition"),
                "node": res.get("node"),
                "replicas": res.get("replicas"),
                "images": [c.get("image") for c in containers],
                "env": [c.get("env") for c in containers],
                "pull_secrets": spec.get("imagePullSecrets"),
            }
        )
 
    for node in nodes:
        endpoints.add(node.get("internal_ip"))
 
    submitted_by = bundle.get("submitted_by")
    if CONFIG["redact_cluster_identifiers"]:
        submitted_by = mask(submitted_by)
 
    case = {
        "service": SERVICE,
        "version": VERSION,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "bundle_id": bundle.get("bundle_id"),
        "submitted_by": submitted_by,
        "cluster": bundle.get("cluster"),
        "item_count": len(items),
        "namespaces": list(namespaces),
        "images": list(images),
        "endpoints": list(endpoints),
        "items": items,
        "events": events,
        "log_excerpts": excerpts,
    }
 
    if CONFIG["echo_bundle"]:
        case["raw_bundle"] = evidence
 
    return case
 
 
class IntakeHandler(BaseHTTPRequestHandler):
    server_version = "%s/%s" % (SERVICE, VERSION)
 
    def _send(self, status, payload):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
 
    def do_POST(self):
        route = self.path.split("?")[0]
        if route != "/intake":
            self._send(404, {"error": "no such route"})
            return
        length = int(self.headers.get("Content-Length", 0))
        bundle = json.loads(self.rfile.read(length))
        self._send(200, build_case(bundle))
 
 
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
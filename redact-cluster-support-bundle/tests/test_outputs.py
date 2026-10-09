"""Verifier for redact-cluster-support-bundle.

The agent is given three sample bundles with the summaries the release desk
cleared for them, plus the estate's ranges, suffixes and env-var hints in the
service config. Every behaviour asserted here is shown at least once in those
cleared summaries or fixed by that config; what is held out is the data and
the combinations (an address form applied to a node address outside the
ranges, a payload nested under a gzipped one, a hyphenated node family, and
so on).

Every graded bundle is generated at grade time. Nothing is replayed from the
sample bundles shipped in the agent image, so a service tuned to the samples
cannot pass. The generator records what it planted, and the assertions compare
the response against that record. The agent's own service is executed and
driven over HTTP; nothing here reimplements redaction.

Each test starts its own copy of the service. Before and after every run, all
processes and files belonging to the service account are removed, so nothing
one run leaves behind can be read by another.
"""

from __future__ import annotations

import base64
import gzip
import http.client
import json
import os
import pwd
import random
import re
import shutil
import signal
import socket
import string
import subprocess
import sys
import tempfile
import time

import pytest

ARTIFACT = os.environ.get("SLUICE_ARTIFACT", "/app/sluice/intake_server.py")
TESTS_DIR = os.environ.get("SLUICE_TESTS_DIR", "/tests")
SERVICE_USER = "sluicesvc"

SUFFIXES = [".mesa.internal", ".svc.cluster.local", ".cluster.local"]
UPSTREAM = ["quay.io", "registry.redhat.io", "ghcr.io", "docker.io"]
# One entry per /16 of every configured range, so the whole of each range is exercised.
CLUSTER_PREFIXES = ["10.21", "10.44", "10.128", "10.129", "10.130", "10.131", "172.30", "127"]
# Private space that borders the configured ranges but is not the estate's.
NEIGHBOUR_PREFIXES = ["10.20", "10.22", "10.43", "10.45", "10.127", "10.132", "172.29", "172.31"]
PUBLIC_PREFIXES = ["151.101", "104.18", "23.215"]
# One env-var name per configured hint, each containing that hint and no other.
SECRET_ENV_NAMES = ["DB_PASS", "APP_SECRET", "API_TOKEN", "AWS_CREDENTIALS", "REGISTRY_AUTH", "SESSION_KEY"]
CONDITIONS = ["EtcdMembersDegraded", "APIServerUnavailable", "NodeNotReady", "CrashLoopBackOff",
              "FailedMount", "ImagePullBackOff", "PodPending"]

ITEM_KEYS = {"resource_id", "kind", "namespace", "name", "condition", "node"}
EVENT_KEYS = {"event_id", "reason", "namespace", "message"}
LOG_KEYS = {"source", "line"}

LEAK_GROUPS = ["declared identifiers", "node names", "hostnames", "addresses",
               "reverse-DNS names of cluster addresses", "reverse-DNS names of node addresses",
               "MAC addresses", "credentials and accounts"]


# ---------------------------------------------------------------------------
# Bundle generation
# ---------------------------------------------------------------------------


def _w(rng, n):
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(n))


def _alnum(rng, n):
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))


def _hex(rng, n):
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _mac(rng):
    return ":".join("%02x" % rng.randrange(256) for _ in range(6))


def reverse_name(address):
    """The reverse-DNS form of an IPv4 address."""
    return ".".join(reversed(address.split("."))) + ".in-addr.arpa"


def reverse_octets(address):
    return ".".join(reversed(address.split(".")))


class Addresses:
    """Hands out distinct addresses.

    The last octet is kept in 20..99 so that the octets of a reverse-DNS name,
    read forwards, never fall inside a cluster range or equal a node address:
    every reverse-DNS name planted here has exactly one reading.
    """

    def __init__(self, rng):
        self.rng = rng
        self.used = set()

    def take(self, prefix):
        while True:
            if prefix == "127":
                value = "127.%d.%d.%d" % (self.rng.randrange(1, 254), self.rng.randrange(1, 254),
                                          self.rng.randrange(20, 100))
            else:
                value = "%s.%d.%d" % (prefix, self.rng.randrange(1, 254), self.rng.randrange(20, 100))
            if value not in self.used:
                self.used.add(value)
                return value


DATA_URL = re.compile(r"data:[^,\s\"']*;base64,([A-Za-z0-9+/]+={0,2})")
GZIP_MAGIC = b"\x1f\x8b"


def b64enc(data):
    return base64.b64encode(data).decode("ascii")


def data_url(text, gz=None, header="data:text/plain;charset=utf-8;base64,"):
    """A data URL carrying `text`; gz is None or (compresslevel, mtime)."""
    raw = text.encode("utf-8")
    if gz:
        raw = gzip.compress(raw, compresslevel=gz[0], mtime=gz[1])
        header = "data:;base64,"
    return header + b64enc(raw)


def open_payload(payload):
    """(text or None, was_gzipped) for one base64 payload."""
    try:
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=True)
    except Exception:
        return None, False
    gzipped = raw[:2] == GZIP_MAGIC
    try:
        return (gzip.decompress(raw) if gzipped else raw).decode("utf-8"), gzipped
    except Exception:
        return None, gzipped


def expanded(text):
    """`text` plus the decoded content of every data URL in it, recursively."""
    parts = [text]
    for match in DATA_URL.finditer(text):
        inner, _ = open_payload(match.group(1))
        if inner is not None:
            parts.append(expanded(inner))
    return "\n".join(parts)


def unfolded(text):
    """`text` with every decodable data-URL payload replaced, in place and
    recursively, by what it decodes to, marked with how it was encoded."""
    def swap(match):
        inner, gzipped = open_payload(match.group(1))
        if inner is None:
            return match.group(0)
        head = match.group(0)[: match.start(1) - match.start(0)]
        return "%s\x01%s:%s\x02" % (head, "gzip" if gzipped else "plain", unfolded(inner))
    return DATA_URL.sub(swap, text)


QUAD = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def pieces(value):
    """The parts of a sensitive value that a partial replacement would leave
    behind: three octets of an address, or the ends and halves of anything else."""
    if QUAD.fullmatch(value):
        octets = value.split(".")
        return [".".join(octets[:3]) + ".", "." + ".".join(octets[1:])]
    found = []
    if len(value) >= 8:
        found += [value[:6], value[-6:]]
    if len(value) >= 12:
        found += [value[: len(value) // 2], value[len(value) // 2:]]
    return sorted(set(found))


class Truth:
    """What the generator planted."""

    def __init__(self):
        self.leaks = []      # (group, label, string): must not appear in the response text
        self.spans = set()   # every sensitive string as written in the bundle
        self.preserved = {}  # label -> string that must survive
        self.info = {}

    def sensitive(self, group, label, value):
        self.leaks.append((group, label, value))
        self.spans.add(value)

    def add_partial_leaks(self, carried):
        """Replacing only part of a value still gives the rest away. A piece
        that also occurs in the text around the planted values is left out, so
        nothing that legitimately stays can be mistaken for a leak."""
        rest = "\n".join(unfolded(text) for text in carried)
        for value in sorted(self.spans, key=lambda v: (-len(v), v)):
            rest = rest.replace(value, "\x00")
        for group, label, value in list(self.leaks):
            if value not in self.spans:
                continue
            for piece in pieces(value):
                if piece not in rest:
                    self.leaks.append((group, "part of the %s" % label, piece))

    def keep(self, label, value):
        self.preserved[label] = value


def generate(seed, nonce=0):
    """Build a fresh bundle; retried with a new nonce in the rare case a
    planted payload happens to look like one of the credential forms."""
    bundle, truth = _generate(seed, nonce)
    for url in truth.info["payload_urls"]:
        body = url.split(",", 1)[1]
        if body.startswith("eyJ") or re.search(r"[+/]eyJ|hvs\.", body):
            return generate(seed, nonce + 1)
    return bundle, truth


def _generate(seed, nonce=0):
    """Build a fresh bundle plus a record of what it contains.

    Every sensitive class is planted in a field the response must carry
    (name, node, message or line), each one where no other rule would
    incidentally catch it; every preserved class likewise.
    """
    rng = random.Random("bundle:%d:%d" % (seed, nonce))
    addrs = Addresses(rng)
    t = Truth()

    cluster_name = "%s-%s" % (_w(rng, 4), _w(rng, 5))
    domain = _w(rng, 6)
    node_prefix = "%s-%s" % (_w(rng, 4), _w(rng, 4)) if (seed // 2) % 2 else _w(rng, 5)
    infra_tail = _alnum(rng, 7)
    infra_id = "%s-%s" % (cluster_name, infra_tail)
    api_url = "https://api.%s.mesa.internal:6443" % cluster_name
    # A mirror host deliberately not under an internal suffix: only the
    # declared cluster.mirror_registry value makes it sensitive.
    mirror = "%s.example.net:5000" % _w(rng, 7)
    collected_by = "%s\\%s.%s" % (domain.upper(), _w(rng, 2), _w(rng, 6))
    submitted_by = "%s-ops" % _w(rng, 6)
    bundle_id = "SB-2026%02d%02d-%04d" % (rng.randrange(1, 13), rng.randrange(1, 29), rng.randrange(1, 9999))
    service_account = "system:serviceaccount:%s:%s" % (_w(rng, 6), _w(rng, 6))
    for label, value in (("cluster name", cluster_name), ("infra id", infra_id), ("api url", api_url),
                         ("mirror registry", mirror), ("collected_by account", collected_by),
                         ("submitted_by account", submitted_by), ("bundle id", bundle_id)):
        t.sensitive("declared identifiers", label, value)
    t.leaks.append(("declared identifiers", "the part of the infra id after the cluster name", "-" + infra_tail))

    node_names, node_ips, node_macs, nodes = [], [], [], []
    for index in range(rng.randrange(2, 5)):
        short = "%s-%02d" % (node_prefix, 10 + index)
        fqdn = "%s.%s.mesa.internal" % (short, cluster_name)
        # Node 0 sits outside every configured range; only its declaration as
        # a node internal_ip makes it sensitive.
        ip = addrs.take("192.168" if index == 0 else CLUSTER_PREFIXES[index % len(CLUSTER_PREFIXES)])
        mac = _mac(rng)
        node_names.append((short, fqdn))
        node_ips.append(ip)
        node_macs.append(mac)
        nodes.append(
            {
                "name": fqdn,
                "internal_ip": ip,
                "mac": mac,
                "kubelet": "v1.%d.%d" % (rng.randrange(25, 33), rng.randrange(0, 9)),
                "os": "RHCOS 416.94.2026%04d-0" % rng.randrange(1000, 9999),
                "conditions": [{"type": "Ready", "status": "True" if index % 2 else "False",
                                "message": "kubelet on %s" % fqdn}],
            }
        )
        t.sensitive("node names", "node %s" % short, short)
        t.sensitive("node names", "node fqdn %s" % short, fqdn)
        t.sensitive("addresses", "node address %d" % index, ip)
        t.sensitive("MAC addresses", "mac %d" % index, mac)
    unlisted = "%s-%02d" % (node_prefix, 70 + seed % 20)
    t.sensitive("node names", "unlisted node", unlisted)
    upper_fqdn = node_names[1][1].upper()
    t.sensitive("node names", "node hostname in upper case", upper_fqdn)
    upper_mac = node_macs[1].upper()
    t.sensitive("MAC addresses", "node MAC in upper case", upper_mac)

    namespaces = [_w(rng, 7) for _ in range(3)]
    reasons = ["%s%s" % (_w(rng, 4).capitalize(), _w(rng, 5).capitalize()) for _ in range(3)]
    key_path = "/etc/%s/%s.pem" % (_w(rng, 5), _w(rng, 6))
    region = "zone-%s" % _w(rng, 6)
    resources = []
    for index in range(rng.randrange(4, 8)):
        short, fqdn = node_names[index % len(node_names)]
        names = SECRET_ENV_NAMES if index == 0 else [SECRET_ENV_NAMES[(seed + index) % len(SECRET_ENV_NAMES)]]
        resources.append(
            {
                "resource_id": "RES-%s" % _alnum(rng, 6),
                "kind": rng.choice(["Pod", "Deployment", "DaemonSet", "StatefulSet"]),
                "namespace": namespaces[index % len(namespaces)],
                "name": "%s-%s" % (_w(rng, 5), short),
                "condition": CONDITIONS[index % len(CONDITIONS)],
                "node": fqdn,
                "replicas": {"desired": rng.randrange(1, 9), "ready": 0 if index % 2 else 2},
                "spec": {
                    "containers": [
                        {
                            "name": _w(rng, 5),
                            "image": "%s/%s/%s@sha256:%s"
                            % (UPSTREAM[index % len(UPSTREAM)], _w(rng, 5), _w(rng, 6), _hex(rng, 64)),
                            "env": [{"name": name, "value": _alnum(rng, 18)} for name in names] + [
                                {"name": "TLS_KEY_FILE", "value": key_path},
                                {"name": "REGION_LABEL", "value": region},
                            ],
                        }
                    ],
                    # Metadata inside spec is not a resource entry of its own.
                    "template": {"resource_id": "RES-%s" % _alnum(rng, 6), "kind": "ReplicaSet"},
                },
            }
        )
    env_secrets = {var["name"]: var["value"] for var in resources[0]["spec"]["containers"][0]["env"][:6]}
    env_secret_2 = resources[1]["spec"]["containers"][0]["env"][0]["value"]
    for name, value in env_secrets.items():
        t.sensitive("credentials and accounts", "value of env var %s" % name, value)

    bearer = _alnum(rng, 22)
    vault = "hvs.%s" % _alnum(rng, 20)
    pull_secret = b64enc(json.dumps(
        {"auths": {mirror: {"auth": b64enc(("%s:%s" % (_w(rng, 5), _alnum(rng, 12))).encode())}}},
        separators=(",", ":")).encode())
    assert pull_secret.startswith("eyJ")
    for label, value in (("bearer token", bearer), ("vault token", vault), ("pull secret", pull_secret),
                         ("service account", service_account)):
        t.sensitive("credentials and accounts", label, value)

    # One internal hostname under each configured suffix.
    hosts = [
        "%s.mesa.internal" % _w(rng, 8),
        "%s.%s.svc.cluster.local" % (_w(rng, 7), namespaces[0]),
        "%s.%s.pod.cluster.local" % (_w(rng, 7), namespaces[1]),
    ]
    for host, suffix in zip(hosts, SUFFIXES):
        t.sensitive("hostnames", "host under %s" % suffix, host)
        t.leaks.append(("hostnames", "first label of the host under %s" % suffix, host.split(".")[0]))
        t.leaks.append(("hostnames", "suffix %s left behind" % suffix, suffix))
    # A public name that only contains a suffix part-way through is not internal.
    lookalike = "%s.cluster.local.%s.example.org" % (_w(rng, 6), _w(rng, 5))

    version = "4.%d.%d" % (rng.randrange(10, 20), rng.randrange(0, 20))
    errata = "%s-2026:%d" % (rng.choice(["RHBA", "RHSA", "RHEA"]), rng.randrange(1000, 9999))
    issue_url = "https://%s/browse/%s-%d" % (
        rng.choice(["issues.redhat.com", "github.com/acme/project", "bugzilla.redhat.com"]),
        _w(rng, 5).upper(),
        rng.randrange(100, 99999),
    )
    mirror_digest = "sha256:%s" % _hex(rng, 64)
    digest512 = "sha512:%s" % _hex(rng, 128)
    upstream_ref = "%s/%s/%s@%s" % (UPSTREAM[seed % len(UPSTREAM)], _w(rng, 5), _w(rng, 5), digest512)

    # Addresses written in their other forms.
    port_addr = addrs.take("10.44")
    ptr_addr = addrs.take("10.21")
    subnet = "%s.%d.0" % (rng.choice(["10.128", "10.129", "10.130", "10.131"]), 2 * rng.randrange(1, 120))
    range_lo, range_hi = addrs.take("10.21"), addrs.take("10.21")
    public = addrs.take(PUBLIC_PREFIXES[seed % len(PUBLIC_PREFIXES)])
    public_net = "%s.0.0/16" % PUBLIC_PREFIXES[seed % len(PUBLIC_PREFIXES)]
    neighbours = [addrs.take(prefix) for prefix in NEIGHBOUR_PREFIXES]
    for label, value in (("address with a port", port_addr), ("network address of a range", subnet),
                         ("low end of a range", range_lo), ("high end of a range", range_hi)):
        t.sensitive("addresses", label, value)
    # The forward address never appears; only its reverse-DNS name does.
    t.leaks.append(("reverse-DNS names of cluster addresses", "address behind a reverse-DNS name", ptr_addr))
    t.sensitive("reverse-DNS names of cluster addresses", "reverse-DNS octets of a cluster address",
                reverse_octets(ptr_addr))
    t.sensitive("reverse-DNS names of node addresses", "reverse-DNS octets of a node address",
                reverse_octets(node_ips[0]))

    events = [
        {
            "event_id": "EV-%s" % _alnum(rng, 5),
            "reason": reasons[0],
            "namespace": namespaces[0],
            "count": rng.randrange(1, 900),
            "message": "pull from %s/%s/%s@%s failed: unauthorized; seen from %s"
            % (mirror, _w(rng, 4), _w(rng, 5), mirror_digest, node_macs[0]),
        },
        {
            "event_id": "EV-%s" % _alnum(rng, 5),
            "reason": reasons[1],
            "namespace": namespaces[1],
            "count": rng.randrange(1, 900),
            "message": "probe to %s (%s) failed; %s is healthy" % (hosts[1], node_ips[1], upstream_ref),
        },
        {
            "event_id": "EV-%s" % _alnum(rng, 5),
            "reason": reasons[2],
            "namespace": namespaces[2],
            "count": rng.randrange(1, 900),
            "message": "Get \"https://%s:%d/healthz\": dial tcp %s:%d: connection refused"
            % (port_addr, 10250, port_addr, 10250),
        },
        # Runtime errors arrive as several lines, the last one ending in a newline.
        {
            "event_id": "EV-%s" % _alnum(rng, 5),
            "reason": reasons[0],
            "namespace": namespaces[1],
            "count": rng.randrange(1, 900),
            "message": "failed to set up sandbox network:\n  plugin type=\"%s\" failed (add): no reply from %s:9107 on %s\n"
            % (_w(rng, 6), node_ips[1], node_names[1][0]),
        },
    ]
    excerpts = [
        {"source": _w(rng, 6), "line": "collecting cluster %s id %s via %s" % (cluster_name, infra_id, api_url)},
        {"source": _w(rng, 6), "line": "peer %s unreachable from %s" % (unlisted, node_names[0][0])},
        # Leading and trailing spaces are part of the line.
        {"source": "kubelet", "line": "  lease for %s renewed through %s  " % (node_names[1][0], node_names[0][0])},
        {"source": _w(rng, 6), "line": "%s paged %s; %s acknowledged for %s and again for %s"
                                       % (submitted_by, collected_by, submitted_by, infra_id, infra_id)},
        {"source": _w(rng, 6), "line": "drain %s, then %s, then %s again" % (node_names[0][0], unlisted, node_names[0][0])},
        {"source": "iptables", "line": "ACCEPT\ttcp  --  %s\t%s  dpt:%d" % (public, port_addr, 6443)},
        {"source": _w(rng, 6), "line": "Authorization: Bearer %s; retrying against %s" % (bearer, hosts[0])},
        {"source": _w(rng, 6), "line": "vault %s pull secret %s" % (vault, pull_secret)},
        {"source": _w(rng, 6), "line": "cached %s; Authorization: Bearer %s" % (vault, vault)},
        {"source": _w(rng, 6), "line": "bundle %s submitted by %s as %s collected by %s"
                                       % (bundle_id, submitted_by, service_account, collected_by)},
        {"source": _w(rng, 6), "line": "running %s version %s; see %s and %s" % (upstream_ref, version, errata, issue_url)},
        {"source": _w(rng, 6), "line": "key file %s; region %s; runbook https://%s/guide"
                                       % (key_path, region, lookalike)},
        {"source": _w(rng, 6), "line": "resolver answered for %s and %s" % (hosts[2], hosts[1])},
        {"source": "sshd", "line": "reverse mapping checking getaddrinfo for %s failed" % upper_fqdn},
        {"source": "arp", "line": "%s is at %s on br-ex" % (node_ips[1], upper_mac)},
        {"source": "cloud-init", "line": "metadata service at 169.254.169.254:80 unreachable; bridge virbr0 192.168.122.1 up"},
        {"source": "coredns", "line": "[INFO] %s:%d - %d \"PTR IN %s. udp 44 false 512\" NXDOMAIN"
                                      % (node_ips[1], rng.randrange(30000, 60000), rng.randrange(1000, 9999),
                                         reverse_name(ptr_addr))},
        {"source": "coredns", "line": "[INFO] lookup \"PTR IN %s.\" for kubelet %s NOERROR"
                                      % (reverse_name(node_ips[0]), node_names[0][0])},
        {"source": "coredns", "line": "[INFO] upstream \"PTR IN %s.\" NOERROR via %s:53"
                                      % (reverse_name(public), public)},
        {"source": "ovnkube", "line": "node subnet %s/23 allocated; egress to %s allowed; kubelet at %s:10250"
                                      % (subnet, public_net, node_ips[0])},
        {"source": "metallb", "line": "pool assigned %s-%s; upstream check %s:443 ok" % (range_lo, range_hi, public)},
        {"source": "ovnkube", "line": "routes outside the estate: %s" % " ".join(neighbours)},
    ]
    for name, value in env_secrets.items():
        excerpts.append({"source": _w(rng, 6), "line": "container %s exited: credential %s rejected" % (_w(rng, 5), value)})
    for index, ip in enumerate(node_ips):
        excerpts.append({"source": "addr%d" % index, "line": "endpoint %s and %s" % (ip, node_macs[index])})
    stray_mac = _mac(rng)
    t.sensitive("MAC addresses", "undeclared mac", stray_mac)
    stray_ips = [addrs.take(prefix) for prefix in CLUSTER_PREFIXES]
    excerpts.append({"source": "stray-mac", "line": "adapter %s seen on the wire" % stray_mac})
    for prefix, ip in zip(CLUSTER_PREFIXES, stray_ips):
        t.sensitive("addresses", "undeclared address in %s" % prefix, ip)
        excerpts.append({"source": "stray-ip", "line": "peer %s answered" % ip})
    registry_refs = {}
    for index, host in enumerate(UPSTREAM):
        ref = "%s/%s/%s@sha256:%s" % (host, _w(rng, 5), _w(rng, 5), _hex(rng, 64))
        registry_refs[host] = ref
        excerpts.append({"source": "crio", "line": "pulled %s ok" % ref})

    # File contents carried as data URLs. Sensitive ones must be sanitized in
    # place; clean and non-text ones must come back byte for byte.
    keep = [_w(rng, 9) for _ in range(6)]
    gz_a = (rng.choice([1, 6, 9]), 1700000000 + rng.randrange(10 ** 7))
    gz_b = (rng.choice([1, 6, 9]), 1700000000 + rng.randrange(10 ** 7))
    payload_addr = addrs.take("10.44")
    payload_host = "%s.mesa.internal" % _w(rng, 8)
    nested_addr = addrs.take("172.30")
    registries = data_url(
        "# %s\n[[registry]]\nprefix = \"%s/%s\"\nlocation = \"%s/%s\"\n"
        % (keep[0], UPSTREAM[seed % len(UPSTREAM)], keep[1], mirror, keep[1])
    )
    chrony = data_url(
        "# %s\npool %s.pool.ntp.org iburst\nserver %s iburst\nserver %s:123\n"
        % (keep[2], _w(rng, 5), payload_host, payload_addr),
        gz=gz_a,
    )
    inner = data_url("apiServer: %s\nnode: %s\nvip: %s\ntoken: %s\n# %s\n"
                     % (api_url, unlisted, nested_addr, env_secret_2, keep[3]),
                     gz=gz_b if seed % 2 else None)
    ignition = data_url(
        "# %s\nstorage:\n  files:\n    - path: /etc/kubernetes/%s.conf\n      contents: %s\n      mode: 420\n"
        % (keep[4], keep[5], inner),
        gz=None if seed % 2 else gz_b,
    )
    clean_gz = data_url("# managed\npool %s.pool.ntp.org iburst\nmakestep 1.0 3\n" % _w(rng, 6),
                        gz=(1, 1700000000 + rng.randrange(10 ** 7)))
    clean_text = data_url("[Unit]\nDescription=%s\nAfter=network-online.target\n" % _w(rng, 8))
    binary = "data:application/octet-stream;base64," + b64enc(
        b"\x89PNG\r\n\x1a\n\xff\xfe" + bytes(rng.randrange(128, 256) for _ in range(48))
    )
    for path, url in (("registries.conf", registries), ("chrony.conf", chrony), ("ignition", ignition),
                      ("chrony.d/pool.conf", clean_gz), ("systemd/unit", clean_text), ("logo.png", binary)):
        excerpts.append({"source": "machine-config-daemon",
                         "line": "writing file /etc/%s contents %s mode 0644" % (path, url)})
    for label, value in (("address inside a gzipped payload", payload_addr),
                         ("hostname inside a gzipped payload", payload_host),
                         ("address inside a nested payload", nested_addr),
                         ("env secret inside a nested payload", env_secret_2)):
        t.sensitive("payload contents", label, value)

    bundle = {
        "bundle_id": bundle_id,
        "schema_version": "2.0",
        "submitted_by": submitted_by,
        "debug": True,
        "cluster": {
            "name": cluster_name,
            "version": version,
            "api_url": api_url,
            "infra_id": infra_id,
            "mirror_registry": mirror,
            "collected_by": collected_by,
        },
        "evidence": {"resources": resources, "nodes": nodes, "events": events, "log_excerpts": excerpts},
    }

    for label, value in (
        ("upstream reference", upstream_ref), ("sha512 digest", digest512),
        ("digest of a mirrored image", mirror_digest), ("version", version), ("errata", errata),
        ("issue url", issue_url), ("absolute-path env value", key_path),
        ("value of an env var that is not a credential", region),
        ("public name that only contains an internal suffix part-way", lookalike),
        ("link-local metadata address", "169.254.169.254:80"),
        ("private address that is not the estate's", "virbr0 192.168.122.1 up"),
        ("public address in reverse-DNS form", reverse_name(public)),
        ("public address with a port", "%s:443" % public), ("public address", "via %s:53" % public),
        ("public range", public_net),
        ("gzipped payload with nothing sensitive (byte for byte)", clean_gz),
        ("text payload with nothing sensitive (byte for byte)", clean_text),
        ("non-text payload (byte for byte)", binary),
    ):
        t.keep(label, value)
    for prefix, ip in zip(NEIGHBOUR_PREFIXES, neighbours):
        t.keep("private address in %s, next to a configured range" % prefix, ip)
    for host, ref in registry_refs.items():
        t.keep("upstream reference %s" % host, ref)
    for index, word in enumerate(keep):
        t.keep("non-sensitive text %d inside a sanitized payload" % index, word)

    t.add_partial_leaks(
        [text for res in resources for text in (res["name"], res["node"])]
        + [event["message"] for event in events]
        + [excerpt["line"] for excerpt in excerpts]
    )
    t.info = {
        "node_names": node_names, "node_ips": node_ips, "node_macs": node_macs, "unlisted": unlisted,
        "hosts": hosts, "lookalike": lookalike, "port_addr": port_addr, "ptr_addr": ptr_addr,
        "subnet": subnet, "range": (range_lo, range_hi), "stray_ips": stray_ips, "stray_mac": stray_mac,
        "collected_by": collected_by, "service_account": service_account, "vault": vault, "bearer": bearer,
        "pull_secret": pull_secret, "env_secrets": env_secrets,
        "payload_urls": [registries, chrony, ignition, inner, clean_gz, clean_text, binary],
    }
    return bundle, t


# ---------------------------------------------------------------------------
# Running the agent's service
# ---------------------------------------------------------------------------


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def service_uid():
    try:
        return pwd.getpwnam(SERVICE_USER).pw_uid
    except KeyError:
        return None


_WRITABLE = None


def writable_places(uid):
    """Directories the service account can create things in, found once."""
    global _WRITABLE
    if _WRITABLE is None:
        gid = pwd.getpwuid(uid).pw_gid
        found = []
        for root, dirs, _ in os.walk("/", topdown=True):
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in ("/proc", "/sys")]
            try:
                info = os.lstat(root)
            except OSError:
                continue
            if info.st_uid == uid or info.st_mode & 0o002 or (info.st_gid == gid and info.st_mode & 0o020):
                found.append(root)
        _WRITABLE = found
    return _WRITABLE


def purge_service_state():
    """Kill every process and delete every file that belongs to the service account,
    so one run of the submitted service can leave nothing for the next."""
    uid = service_uid()
    if os.geteuid() != 0 or uid is None:
        return
    for _ in range(20):
        alive = False
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                if os.stat("/proc/%s" % pid).st_uid == uid:
                    os.kill(int(pid), signal.SIGKILL)
                    alive = True
            except OSError:
                pass
        if not alive:
            break
        time.sleep(0.05)
    left = []
    for place in list(writable_places(uid)):
        for root, dirs, files in os.walk(place, topdown=False):
            for name in files + dirs:
                path = os.path.join(root, name)
                try:
                    if os.lstat(path).st_uid != uid:
                        continue
                    if os.path.isdir(path) and not os.path.islink(path):
                        os.rmdir(path)
                    else:
                        os.unlink(path)
                except OSError:
                    left.append(path)
    assert not left, "could not clear what the service account left behind: %r" % left[:5]
    # System V shared memory, queues and semaphores outlive the process too.
    for kind, column, flag in (("shm", "shmid", "-m"), ("msg", "msqid", "-q"), ("sem", "semid", "-s")):
        try:
            with open("/proc/sysvipc/%s" % kind) as table:
                rows = [row.split() for row in table.read().splitlines()]
        except OSError:
            continue
        if not rows or column not in rows[0] or "uid" not in rows[0]:
            continue
        ident, owner = rows[0].index(column), rows[0].index("uid")
        for row in rows[1:]:
            if int(row[owner]) == uid and shutil.which("ipcrm"):
                subprocess.run(["ipcrm", flag, row[ident]], capture_output=True)


class Service:
    """One isolated run of the submitted service.

    Each instance gets a private scratch directory, runs under -I -S so that
    packages installed for the verifier are not importable by submitted code,
    and is bracketed by purge_service_state(), so no process, file or cache
    from an earlier run can still exist when this one starts.
    """

    def __init__(self):
        self.port = free_port()
        self.root = None
        self.proc = None

    def __enter__(self):
        purge_service_state()
        self.root = tempfile.mkdtemp(prefix="sluice-")
        script = os.path.join(self.root, "intake_server.py")
        shutil.copyfile(ARTIFACT, script)
        os.chmod(script, 0o444)

        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": self.root,
            "TMPDIR": self.root,
        }
        kwargs = {}
        uid = service_uid()
        if os.geteuid() == 0 and uid is not None:
            os.chmod(self.root, 0o1777)
            kwargs["user"] = SERVICE_USER

        self.proc = subprocess.Popen(
            [sys.executable, "-I", "-S", script, "--port", str(self.port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env,
            cwd=self.root,
            **kwargs
        )
        self._await(20.0)
        return self

    def _await(self, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                err = self.proc.stderr.read().decode("utf-8", "replace")[-1500:]
                raise AssertionError(
                    "the service exited immediately (rc=%s); it must start with --port "
                    "using only the standard library.\n%s" % (self.proc.returncode, err)
                )
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("the service never listened on port %d" % self.port)

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.proc and self.proc.stderr:
            self.proc.stderr.close()
        purge_service_state()
        if self.root and os.path.isdir(self.root):
            shutil.rmtree(self.root, ignore_errors=True)
        return False

    def post(self, bundle):
        body = json.dumps(bundle).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=90)
        try:
            conn.request("POST", "/intake", body=body, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()


@pytest.fixture
def service():
    assert os.path.isfile(ARTIFACT), "%s is missing from the collected artifacts" % ARTIFACT
    with Service() as running:
        yield running


def ok(service_, bundle):
    status, body = service_.post(bundle)
    assert status == 200, "a bundle must be accepted; got %d: %r" % (status, body[:300])
    return json.loads(body), body


SEEDS = [3, 17, 41]


# ---------------------------------------------------------------------------
# Response shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_response_has_exactly_the_three_lists(service, seed):
    """Only items, events and log_excerpts, one entry per bundle entry, with exactly the stated fields."""
    bundle, _ = generate(seed)
    case, _ = ok(service, bundle)
    assert isinstance(case, dict) and set(case) == {"items", "events", "log_excerpts"}, (
        "the response must have exactly items, events and log_excerpts; got %r"
        % (sorted(case) if isinstance(case, dict) else type(case).__name__)
    )
    evidence = bundle["evidence"]
    for key, source, fields in (
        ("items", "resources", ITEM_KEYS),
        ("events", "events", EVENT_KEYS),
        ("log_excerpts", "log_excerpts", LOG_KEYS),
    ):
        assert isinstance(case[key], list), "%s must be a list" % key
        assert len(case[key]) == len(evidence[source]), (
            "%s must have one entry per entry in evidence.%s (%d), got %d"
            % (key, source, len(evidence[source]), len(case[key]))
        )
        for entry in case[key]:
            assert isinstance(entry, dict) and set(entry) == fields, (
                "every %s entry must have exactly %r; got %r" % (key, sorted(fields), entry)
            )


@pytest.mark.parametrize("seed", SEEDS)
def test_lists_keep_bundle_order_and_copy_identifying_fields(service, seed):
    """The fields that are never changed come back unchanged and in bundle order."""
    bundle, _ = generate(seed)
    case, _ = ok(service, bundle)
    evidence = bundle["evidence"]
    for key, source, copied in (
        ("items", "resources", ("resource_id", "kind", "namespace", "condition")),
        ("events", "events", ("event_id", "reason", "namespace")),
        ("log_excerpts", "log_excerpts", ("source",)),
    ):
        got = [tuple(entry.get(f) for f in copied) for entry in case[key]]
        want = [tuple(entry[f] for f in copied) for entry in evidence[source]]
        assert got == want, (
            "%s must copy %r unchanged and keep bundle order;\n got  %r\n want %r" % (key, copied, got, want)
        )


# ---------------------------------------------------------------------------
# Redaction and preservation
# ---------------------------------------------------------------------------


def response_text(service_, bundle, truth):
    """(every string of the response, what its data-URL payloads decode to).

    The one planted public hostname that contains an internal suffix part-way
    through is taken out first, so the suffix check is not tripped by it."""
    _, body = ok(service_, bundle)
    case = json.loads(body)
    plain = "\n".join(
        str(v) for key in ("items", "events", "log_excerpts") for entry in case[key] for v in entry.values()
    ).replace(truth.info["lookalike"], "")
    return plain, expanded(plain)[len(plain):]


@pytest.mark.parametrize("group", LEAK_GROUPS)
def test_no_sensitive_value_survives(service, group):
    """Nothing planted from this class of sensitive value is left in the response text."""
    leaked = {}
    for seed in SEEDS:
        bundle, truth = generate(seed)
        plain, _ = response_text(service, bundle, truth)
        found = sorted(label for g, label, value in truth.leaks if g == group and value in plain)
        if found:
            leaked[seed] = found
    assert not leaked, "%s reached the summary (by seed): %r" % (group, leaked)


def test_no_sensitive_value_survives_inside_payloads(service):
    """Decoding every data-URL payload in the response, recursively, turns up nothing sensitive."""
    leaked = {}
    for seed in SEEDS:
        bundle, truth = generate(seed)
        _, inside = response_text(service, bundle, truth)
        found = sorted(label for _, label, value in truth.leaks if value in inside)
        if found:
            leaked[seed] = found
    assert not leaked, "these are still inside data-URL payloads (by seed): %r" % leaked


@pytest.mark.parametrize("seed", SEEDS)
def test_everything_else_survives(service, seed):
    """Every planted non-sensitive value is still there, in plain text or inside a payload."""
    bundle, truth = generate(seed)
    _, body = ok(service, bundle)
    case = json.loads(body)
    text = expanded("\n".join(
        str(v) for key in ("items", "events", "log_excerpts") for entry in case[key] for v in entry.values()
    ))
    missing = sorted(label for label, value in truth.preserved.items() if value not in text)
    assert not missing, "seed %d: redaction destroyed %r" % (seed, missing)


def surrounding_text_kept(original, returned, spans):
    """True when `returned` is `original` with nothing changed except at the
    planted sensitive strings: every stretch of text between them is present,
    unchanged and in order, with something standing where each one was.

    Payloads are compared by what they decode to. No placeholder syntax is
    assumed, and a sensitive string that was left in place still fits; the
    leak tests deal with that."""
    masked = unfolded(original)
    for value in sorted(spans, key=lambda v: (-len(v), v)):
        masked = masked.replace(value, "\x00")
    pattern = "(?:.+?)".join(re.escape(part) for part in re.split("\x00+", masked))
    return re.fullmatch(pattern, unfolded(returned)) is not None


FIELD_CLASSES = ["item names and nodes", "event messages", "log lines", "log lines carrying payloads"]


@pytest.mark.parametrize("field_class", FIELD_CLASSES)
def test_only_sensitive_values_change(service, field_class):
    """Each returned field is its original with only the sensitive values replaced:
    the wording, spacing and punctuation around them are exactly as they were,
    entry by entry in bundle order."""
    wrong = []
    for seed in SEEDS:
        bundle, truth = generate(seed)
        case, _ = ok(service, bundle)
        evidence = bundle["evidence"]
        pairs = []
        if field_class == "item names and nodes":
            for src, out in zip(evidence["resources"], case["items"]):
                pairs += [(src["name"], out.get("name")), (src["node"], out.get("node"))]
        elif field_class == "event messages":
            pairs = [(src["message"], out.get("message")) for src, out in zip(evidence["events"], case["events"])]
        else:
            carrying = field_class == "log lines carrying payloads"
            pairs = [(src["line"], out.get("line"))
                     for src, out in zip(evidence["log_excerpts"], case["log_excerpts"])
                     if bool(DATA_URL.search(src["line"])) == carrying]
        assert pairs, "nothing to compare for %s" % field_class
        for original, returned in pairs:
            if not isinstance(returned, str) or not surrounding_text_kept(original, returned, truth.spans):
                shown = returned if not isinstance(returned, str) else returned[:160]
                wrong.append("seed %d: %r came back as %r" % (seed, original[:160], shown))
    assert not wrong, "%s changed beyond their sensitive values:\n%s" % (field_class, "\n".join(wrong[:6]))


def probe_lines(case, prefix):
    return {x["source"]: x["line"] for x in case["log_excerpts"] if x["source"].startswith(prefix)}


def test_placeholders_are_consistent_and_injective(service):
    """One value, one placeholder; two values, two placeholders.

    Each probe line contains exactly one value, so lines are compared whole:
    no assumption is made about placeholder syntax.
    """
    bundle, truth = generate(11)
    info = truth.info
    probes = {
        "host": info["hosts"][0],
        "addr": info["node_ips"][1],
        "addr2": info["stray_ips"][6],
        "node-addr": info["node_ips"][0],
        "mac": info["node_macs"][0],
        "acct": info["collected_by"],
        "unlisted": info["unlisted"],
        "node-short": info["node_names"][0][0],
        "node-fqdn": info["node_names"][0][1],
        "sa": info["service_account"],
        "vault": info["vault"],
        "pull-secret": info["pull_secret"],
        "cluster": bundle["cluster"]["name"],
        "infra": bundle["cluster"]["infra_id"],
        "bundle": bundle["bundle_id"],
        "submitter": bundle["submitted_by"],
    }
    for name, value in info["env_secrets"].items():
        probes["env-%s" % name] = value
    excerpts = bundle["evidence"]["log_excerpts"]
    for key, value in probes.items():
        excerpts.append({"source": "p-%s-1" % key, "line": value})
        excerpts.append({"source": "p-%s-2" % key, "line": value})
    case, _ = ok(service, bundle)
    lines = probe_lines(case, "p-")

    seen = {}
    for key in probes:
        first, second = lines.get("p-%s-1" % key), lines.get("p-%s-2" % key)
        assert first is not None and second is not None, "probe log excerpts must be reported (%s)" % key
        assert first == second, "%s produced two different placeholders: %r vs %r" % (key, first, second)
        assert probes[key] not in first, "%s: placeholder still contains the value" % key
        value = probes[key]
        assert first[:4] != value[:4] and first[-4:] != value[-4:], (
            "%s: only part of the value was replaced: %r" % (key, first)
        )
        assert first not in seen, "%s and %s collapsed onto the same placeholder %r" % (key, seen[first], first)
        seen[first] = key


def test_same_value_maps_identically_in_different_fields(service):
    """A value gets one placeholder whether it is in an item, an event or a log line."""
    bundle, truth = generate(13)
    info = truth.info
    short, fqdn = info["node_names"][0]
    word = "probe%s" % short[:2]
    bundle["evidence"]["resources"].append(
        {"resource_id": "RES-probe", "kind": "Pod", "namespace": "probes", "name": "%s-%s" % (word, short),
         "condition": "PodPending", "node": fqdn, "replicas": None, "spec": {"containers": []}}
    )
    bundle["evidence"]["events"].append(
        {"event_id": "EV-probe", "reason": "Probing", "namespace": "probes", "count": 1, "message": fqdn}
    )
    bundle["evidence"]["log_excerpts"] += [{"source": "p-fqdn", "line": fqdn}, {"source": "p-short", "line": short}]
    case, _ = ok(service, bundle)
    item = [i for i in case["items"] if i["resource_id"] == "RES-probe"][0]
    event = [e for e in case["events"] if e["event_id"] == "EV-probe"][0]
    lines = probe_lines(case, "p-")
    assert fqdn not in lines["p-fqdn"] and short not in lines["p-short"], "node names were not replaced"
    assert event["message"] == lines["p-fqdn"], (
        "the same host became %r in an event and %r in a log excerpt" % (event["message"], lines["p-fqdn"])
    )
    assert item["node"] == lines["p-fqdn"], (
        "the same host became %r in an item's node and %r in a log excerpt" % (item["node"], lines["p-fqdn"])
    )
    assert item["name"] == "%s-%s" % (word, lines["p-short"]), (
        "an item name must keep its own text and use the node's placeholder: got %r, want %r"
        % (item["name"], "%s-%s" % (word, lines["p-short"]))
    )


def test_hostname_case_does_not_matter(service):
    """DNS names are the same name in any case, so they share a placeholder."""
    bundle, truth = generate(19)
    fqdn = truth.info["node_names"][0][1]
    host = truth.info["hosts"][0]
    excerpts = bundle["evidence"]["log_excerpts"]
    for key, value in (("fqdn", fqdn), ("host", host)):
        excerpts.append({"source": "c-%s-lower" % key, "line": "peer %s ok" % value})
        excerpts.append({"source": "c-%s-upper" % key, "line": "peer %s ok" % value.upper()})
    case, _ = ok(service, bundle)
    lines = probe_lines(case, "c-")
    for key, value in (("fqdn", fqdn), ("host", host)):
        lower, upper = lines["c-%s-lower" % key], lines["c-%s-upper" % key]
        assert value not in lower and value.upper() not in upper, "%s was not replaced in both cases" % value
        assert lower == upper, "%s in upper case became %r but %r in lower case" % (value, upper, lower)


def test_mac_case_does_not_matter(service):
    """A MAC address is the same address in upper or lower case, so it has one placeholder."""
    bundle, truth = generate(43)
    excerpts = bundle["evidence"]["log_excerpts"]
    macs = {"node": truth.info["node_macs"][0], "stray": truth.info["stray_mac"]}
    for key, value in macs.items():
        excerpts.append({"source": "m-%s-lower" % key, "line": "peer %s ok" % value})
        excerpts.append({"source": "m-%s-upper" % key, "line": "peer %s ok" % value.upper()})
    case, _ = ok(service, bundle)
    lines = probe_lines(case, "m-")
    for key, value in macs.items():
        lower, upper = lines["m-%s-lower" % key], lines["m-%s-upper" % key]
        assert value not in lower and value.upper() not in upper, "%s was not replaced in both cases" % value
        assert lower == upper, "%s in upper case became %r but %r in lower case" % (value, upper, lower)


def test_token_after_bearer_is_the_same_token(service):
    """What follows "Bearer" is replaced up to the end of the token and no
    further, and a token that also appears on its own keeps one placeholder."""
    bundle, truth = generate(47)
    vault, bearer = truth.info["vault"], truth.info["bearer"]
    excerpts = bundle["evidence"]["log_excerpts"]
    excerpts += [
        {"source": "b-vault-plain", "line": "peer %s ok" % vault},
        {"source": "b-vault-bearer", "line": "Authorization: Bearer %s; retrying" % vault},
        {"source": "b-bearer-1", "line": "Authorization: Bearer %s; retrying" % bearer},
        {"source": "b-bearer-2", "line": "sent Bearer %s, refused" % bearer},
    ]
    case, _ = ok(service, bundle)
    lines = probe_lines(case, "b-")
    token = placeholder_in(lines["b-vault-plain"], "a vault token")
    assert token and vault not in token, "the vault token was not replaced: %r" % lines["b-vault-plain"]
    assert lines["b-vault-bearer"] == "Authorization: Bearer %s; retrying" % token, (
        "a vault token after Bearer must take the placeholder it has on its own, with the text "
        "after it untouched: got %r" % lines["b-vault-bearer"]
    )
    first, second = lines["b-bearer-1"], lines["b-bearer-2"]
    head_1, tail_1, head_2, tail_2 = "Authorization: Bearer ", "; retrying", "sent Bearer ", ", refused"
    assert first.startswith(head_1) and first.endswith(tail_1) and second.startswith(head_2) and second.endswith(tail_2), (
        "text around a bearer token must be left as it was: got %r and %r" % (first, second)
    )
    got_1, got_2 = first[len(head_1):-len(tail_1)], second[len(head_2):-len(tail_2)]
    assert got_1 and bearer not in first + second, "the bearer token was not replaced: %r" % first
    assert got_1 == got_2, "one bearer token became %r and %r" % (got_1, got_2)
    assert got_1 != token, "two different tokens share the placeholder %r" % token


def placeholder_in(line, label):
    head, tail = "peer ", " ok"
    assert line.startswith(head) and line.endswith(tail), (
        "text around a sensitive value must be left as it was: %s became %r" % (label, line)
    )
    return line[len(head) : -len(tail)]


@pytest.mark.parametrize("seed", SEEDS)
def test_address_forms_share_the_plain_placeholder(service, seed):
    """A port, a prefix length, a range hyphen or .in-addr.arpa stays; the
    address inside is replaced by the placeholder it gets when written plainly."""
    bundle, truth = generate(seed)
    info = truth.info
    port_addr, ptr_addr, subnet = info["port_addr"], info["ptr_addr"], info["subnet"]
    node_addr = info["node_ips"][0]
    lo, hi = info["range"]
    plain = {"port": port_addr, "ptr": ptr_addr, "node": node_addr, "subnet": subnet, "lo": lo, "hi": hi}
    forms = {
        "cluster address with a port": ("%s:6443" % port_addr, "{port}:6443"),
        "node address with a port": ("%s:10250" % node_addr, "{node}:10250"),
        "cluster address in reverse-DNS form": (reverse_name(ptr_addr), "{ptr}.in-addr.arpa"),
        "reverse-DNS name with its trailing dot": (reverse_name(ptr_addr) + ".", "{ptr}.in-addr.arpa."),
        "node address in reverse-DNS form": (reverse_name(node_addr), "{node}.in-addr.arpa"),
        "network address of a range": ("%s/23" % subnet, "{subnet}/23"),
        "hyphenated range": ("%s-%s" % (lo, hi), "{lo}-{hi}"),
    }
    excerpts = bundle["evidence"]["log_excerpts"]
    for key, value in plain.items():
        excerpts.append({"source": "f-plain-%s" % key, "line": "peer %s ok" % value})
    for label, (written, _) in forms.items():
        excerpts.append({"source": "f-form-%s" % label, "line": "peer %s ok" % written})
    case, _ = ok(service, bundle)
    lines = probe_lines(case, "f-")

    placeholders = {}
    for key, value in plain.items():
        token = placeholder_in(lines["f-plain-%s" % key], "a plain address")
        assert token and value not in token, "the plain address %s was not replaced: %r" % (value, token)
        placeholders[key] = token
    assert len(set(placeholders.values())) == len(placeholders), (
        "different addresses shared a placeholder: %r" % placeholders
    )
    wrong = {}
    for label, (_, template) in forms.items():
        got = placeholder_in(lines["f-form-%s" % label], label)
        want = template.format(**placeholders)
        if got != want:
            wrong[label] = "got %r, want %r" % (got, want)
    assert not wrong, "seed %d: address forms were not redacted as the plain address:\n%s" % (
        seed, "\n".join("  %s: %s" % pair for pair in wrong.items())
    )


def payload_of(line, label):
    """The payload of the single data URL in a probe line, with the text around it checked."""
    head, tail = "wrote data:text/plain;base64,", " done"
    assert line.startswith(head) and line.endswith(tail), (
        "text around a data URL must be left as it was: %s became %r" % (label, line[:200])
    )
    return line[len(head) : -len(tail)]


@pytest.mark.parametrize("seed", SEEDS)
def test_payloads_are_sanitized_in_place(service, seed):
    """Inside a data-URL payload only the sensitive values change, they take
    the placeholders the same values get in plain text, and the payload comes
    back in the encoding it arrived in."""
    bundle, truth = generate(seed)
    info = truth.info
    addr, node_addr, ptr_addr = info["port_addr"], info["node_ips"][0], info["ptr_addr"]
    mac = info["node_macs"][0]
    plain = {"addr": addr, "node": node_addr, "ptr": ptr_addr, "mac": mac}
    rng = random.Random("payload-probe:%d" % seed)
    words = [_w(rng, 10) for _ in range(4)]

    def url(text, gz=None):
        raw = text.encode()
        if gz:
            raw = gzip.compress(raw, compresslevel=gz, mtime=1690000000 + seed)
        return "data:text/plain;base64," + b64enc(raw)

    text_src = "server=%s:6443\nmac=%s\nkeep=%s\n" % (addr, mac, words[0])
    text_want = "server={addr}:6443\nmac={mac}\nkeep=%s\n" % words[0]
    gz_src = "peer=%s\nkeep=%s\n" % (node_addr, words[1])
    gz_want = "peer={node}\nkeep=%s\n" % words[1]
    inner_src = "ptr=%s\nkeep=%s\n" % (reverse_name(ptr_addr), words[2])
    inner_want = "ptr={ptr}.in-addr.arpa\nkeep=%s\n" % words[2]
    outer_src = "files:\n- contents: %s\n- keep: %s\n" % (url(inner_src), words[3])
    # A clean, gzipped inner payload under an outer one that does need changing.
    clean_inner = url("makestep 1.0 3\n# %s\n" % words[0], gz=1)
    mixed_src = "server=%s\ncontents: %s\n" % (addr, clean_inner)
    mixed_want = "server={addr}\ncontents: %s\n" % clean_inner

    excerpts = bundle["evidence"]["log_excerpts"]
    for key, value in plain.items():
        excerpts.append({"source": "e-plain-%s" % key, "line": "peer %s ok" % value})
    excerpts.append({"source": "e-text", "line": "wrote %s done" % url(text_src)})
    excerpts.append({"source": "e-gzip", "line": "wrote %s done" % url(gz_src, gz=6)})
    excerpts.append({"source": "e-nested", "line": "wrote %s done" % url(outer_src, gz=9)})
    excerpts.append({"source": "e-mixed", "line": "wrote %s done" % url(mixed_src)})
    case, _ = ok(service, bundle)
    lines = probe_lines(case, "e-")
    tokens = {key: placeholder_in(lines["e-plain-%s" % key], "a plain value") for key in plain}
    for key, value in plain.items():
        assert tokens[key] and value not in tokens[key], "the plain value %s was not replaced" % value

    wrong = {}

    got, gzipped = open_payload(payload_of(lines["e-text"], "a text payload"))
    if gzipped or got != text_want.format(**tokens):
        wrong["text payload"] = "decodes to %r (gzip=%s), want %r" % (got, gzipped, text_want.format(**tokens))

    got, gzipped = open_payload(payload_of(lines["e-gzip"], "a gzipped payload"))
    if not gzipped or got != gz_want.format(**tokens):
        wrong["gzipped payload"] = "decodes to %r (gzip=%s), want gzip of %r" % (got, gzipped, gz_want.format(**tokens))

    outer, gzipped = open_payload(payload_of(lines["e-nested"], "a nested payload"))
    inner_urls = DATA_URL.findall(outer or "")
    inner, inner_gz = open_payload(inner_urls[0]) if len(inner_urls) == 1 else (None, False)
    outer_ok = (
        gzipped and outer is not None and len(inner_urls) == 1
        and outer == "files:\n- contents: data:text/plain;base64,%s\n- keep: %s\n" % (inner_urls[0], words[3])
    )
    if not outer_ok or inner_gz or inner != inner_want.format(**tokens):
        wrong["nested payload"] = "outer decodes to %r (gzip=%s); inner decodes to %r, want %r" % (
            outer, gzipped, inner, inner_want.format(**tokens))

    got, gzipped = open_payload(payload_of(lines["e-mixed"], "a payload holding a clean payload"))
    if gzipped or got != mixed_want.format(**tokens):
        wrong["clean payload inside a changed one"] = "decodes to %r, want %r (inner payload byte for byte)" % (
            got, mixed_want.format(**tokens))

    assert not wrong, "seed %d: data-URL payloads were not sanitized in place:\n%s" % (
        seed, "\n".join("  %s: %s" % pair for pair in wrong.items())
    )


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

# A response that depends on the clock (a gzip header written with the current
# time, for instance) only shows it once the clock has moved on.
CLOCK_STEP = 1.3


def reordered(value):
    """The same content with every object's keys in reverse order."""
    if isinstance(value, dict):
        return {k: reordered(value[k]) for k in reversed(list(value))}
    if isinstance(value, list):
        return [reordered(v) for v in value]
    return value


def test_repeat_is_byte_identical(service):
    """The same bundle sent twice to one process gives the same bytes."""
    bundle, _ = generate(23)
    _, first = ok(service, bundle)
    time.sleep(CLOCK_STEP)
    _, second = ok(service, bundle)
    assert first == second, "the same bundle produced two different responses"


def test_key_order_does_not_matter(service):
    """The same bundle with its keys reordered gives the same bytes."""
    bundle, _ = generate(29)
    _, plain = ok(service, bundle)
    time.sleep(CLOCK_STEP)
    _, shuffled = ok(service, reordered(bundle))
    assert plain == shuffled, "reordering keys changed the response"


def test_restart_reproduces_the_response():
    """A second, separately started service gives the same bytes as the first.

    The first one is stopped and everything its account left behind is removed
    before the second starts, so the second has to compute the response."""
    bundle, _ = generate(31)
    with Service() as first_run:
        _, first = ok(first_run, bundle)
    time.sleep(CLOCK_STEP)
    with Service() as second_run:
        _, second = ok(second_run, bundle)
    assert first == second, "a restarted service produced a different response"


def test_restart_reproduces_the_response_for_reordered_input():
    """A restarted service given the reordered bundle first must still agree."""
    bundle, _ = generate(37)
    with Service() as first_run:
        _, first = ok(first_run, bundle)
    time.sleep(CLOCK_STEP)
    with Service() as second_run:
        _, second = ok(second_run, reordered(bundle))
    assert first == second, "reordered input to a restarted service produced different bytes"


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


def test_service_user_cannot_read_verifier_assets():
    """The account the service runs as cannot open the verifier's test file."""
    if os.geteuid() != 0 or service_uid() is None:
        pytest.skip("privilege separation only applies in the verifier image")
    probe = subprocess.run(
        [sys.executable, "-c", "open(%r).read()" % os.path.join(TESTS_DIR, "test_outputs.py")],
        user=SERVICE_USER,
        capture_output=True,
    )
    assert probe.returncode != 0, "the service account can read the verifier's own files"


def test_third_party_packages_are_not_importable():
    """The submitted service has the standard library and nothing else: the
    verifier's own packages cannot be imported by the account it runs as, in
    the mode it is started in or in any other, even with every directory on
    the verifier's module path added to its own."""
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin"}
    kwargs = {}
    if os.geteuid() == 0 and service_uid() is not None:
        kwargs["user"] = SERVICE_USER
    plain = subprocess.run([sys.executable, "-I", "-S", "-c", "import pytest"], capture_output=True, env=env, **kwargs)
    assert plain.returncode != 0, "third-party packages are importable by submitted code"
    if not kwargs:
        pytest.skip("the directory-permission check only applies in the verifier image")
    reach = (
        "import sys\n"
        "sys.path[:0] = %r\n"
        "found = []\n"
        "for name in %r:\n"
        "    try:\n"
        "        __import__(name)\n"
        "        found.append(name)\n"
        "    except Exception:\n"
        "        pass\n"
        "sys.exit(1 if found else 0)\n" % ([p for p in sys.path if p], ["pytest", "_pytest", "pluggy", "iniconfig", "pip"])
    )
    for flags in (["-I", "-S"], ["-I"], []):
        probe = subprocess.run([sys.executable] + flags + ["-c", reach], capture_output=True, env=env, cwd="/", **kwargs)
        assert probe.returncode == 0, (
            "submitted code can import the verifier's packages by adding their directory to its path "
            "(interpreter flags %r)" % (flags,)
        )
    readable = subprocess.run([sys.executable, "-I", "-S", "-c", "open(%r).read()" % pytest.__file__],
                              capture_output=True, env=env, **kwargs)
    assert readable.returncode != 0, "the service account can read the verifier's packages"

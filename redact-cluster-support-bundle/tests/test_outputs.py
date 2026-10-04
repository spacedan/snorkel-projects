"""Verifier for redact-cluster-support-bundle.

Every graded bundle is generated at grade time. Nothing is replayed from the
sample bundles shipped in the agent image: cluster names, node families,
addresses and the forms they are written in, credentials, encoded file
payloads, resource ids, reasons, namespaces, registries, digests, versions and
errata are all fresh,
so a service tuned to the samples cannot pass. The generator records what it
planted, and the assertions compare the response against that record. The
agent's own service is executed and driven over HTTP; nothing here
reimplements redaction.
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
CLUSTER_PREFIXES = ["10.21", "10.44", "10.128", "172.30", "127"]
PUBLIC_PREFIXES = ["151.101", "104.18", "23.215"]
CONDITIONS = ["EtcdMembersDegraded", "APIServerUnavailable", "NodeNotReady", "CrashLoopBackOff",
              "FailedMount", "ImagePullBackOff", "PodPending"]

ITEM_KEYS = {"resource_id", "kind", "namespace", "name", "condition", "node"}
EVENT_KEYS = {"event_id", "reason", "namespace", "message"}
LOG_KEYS = {"source", "line"}


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


def generate(seed, nonce=0):
    """Build a fresh bundle; retried with a new nonce in the rare case a
    planted payload happens to look like one of the credential forms."""
    bundle, truth = _generate(seed, nonce)
    for url in truth["payload_urls"]:
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

    cluster_name = "%s-%s" % (_w(rng, 4), _w(rng, 5))
    domain = _w(rng, 6)
    suffix = SUFFIXES[seed % len(SUFFIXES)]
    node_prefix = rng.choice([_w(rng, 5), "%s-%s" % (_w(rng, 4), _w(rng, 4))])
    infra_id = "%s-%s" % (cluster_name, _alnum(rng, 5))
    api_url = "https://api.%s.mesa.internal:6443" % cluster_name
    # A mirror host deliberately not under an internal suffix: only the
    # declared cluster.mirror_registry value makes it sensitive.
    mirror = "%s.example.net:5000" % _w(rng, 7)
    collected_by = "%s\\%s.%s" % (domain.upper(), _w(rng, 2), _w(rng, 6))
    submitted_by = "%s-ops" % _w(rng, 6)
    bundle_id = "SB-%s" % _alnum(rng, 8)
    service_account = "system:serviceaccount:%s:%s" % (_w(rng, 6), _w(rng, 6))

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
    unlisted = "%s-%02d" % (node_prefix, 70 + seed % 20)

    namespaces = [_w(rng, 7) for _ in range(3)]
    reasons = ["%s%s" % (_w(rng, 4).capitalize(), _w(rng, 5).capitalize()) for _ in range(3)]
    key_path = "/etc/%s/%s.pem" % (_w(rng, 5), _w(rng, 6))
    resources = []
    for index in range(rng.randrange(4, 8)):
        short, fqdn = node_names[index % len(node_names)]
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
                            "env": [
                                {"name": "APP_SECRET", "value": _alnum(rng, 18)},
                                {"name": "TLS_KEY_FILE", "value": key_path},
                            ],
                        }
                    ]
                },
            }
        )

    env_secret = resources[0]["spec"]["containers"][0]["env"][0]["value"]
    bearer = _alnum(rng, 22)
    vault = "hvs.%s" % _alnum(rng, 20)
    b64 = "eyJ%s==" % _alnum(rng, 40)
    svc_host = "%s.%s%s" % (_w(rng, 7), namespaces[0], suffix)
    plain_internal = "%s.mesa.internal" % _w(rng, 8)
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
    subnet = "10.128.%d.0" % (2 * rng.randrange(1, 120))
    range_lo, range_hi = addrs.take("10.21"), addrs.take("10.21")
    public = addrs.take(PUBLIC_PREFIXES[seed % len(PUBLIC_PREFIXES)])
    public_net = "%s.0.0/16" % PUBLIC_PREFIXES[seed % len(PUBLIC_PREFIXES)]

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
            "message": "probe to %s (%s) failed; %s is healthy" % (svc_host, node_ips[1], upstream_ref),
        },
        {
            "event_id": "EV-%s" % _alnum(rng, 5),
            "reason": reasons[2],
            "namespace": namespaces[2],
            "count": rng.randrange(1, 900),
            "message": "Get \"https://%s:%d/healthz\": dial tcp %s:%d: connection refused"
            % (port_addr, 10250, port_addr, 10250),
        },
    ]
    excerpts = [
        {"source": _w(rng, 6), "line": "collecting cluster %s id %s via %s" % (cluster_name, infra_id, api_url)},
        {"source": _w(rng, 6), "line": "peer %s unreachable from %s" % (unlisted, node_names[0][0])},
        {"source": _w(rng, 6), "line": "Authorization: Bearer %s to %s" % (bearer, plain_internal)},
        {"source": _w(rng, 6), "line": "vault %s pull secret %s" % (vault, b64)},
        {"source": _w(rng, 6), "line": "bundle %s submitted by %s as %s collected by %s"
                                       % (bundle_id, submitted_by, service_account, collected_by)},
        {"source": _w(rng, 6), "line": "running %s version %s; see %s and %s" % (upstream_ref, version, errata, issue_url)},
        {"source": _w(rng, 6), "line": "env secret %s on %s; key file %s" % (env_secret, node_ips[-1], key_path)},
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
    ]
    for index, ip in enumerate(node_ips):
        excerpts.append({"source": "addr%d" % index, "line": "endpoint %s and %s" % (ip, node_macs[index])})
    stray_mac = _mac(rng)
    stray_ips = [addrs.take(prefix) for prefix in CLUSTER_PREFIXES]
    excerpts.append({"source": "stray-mac", "line": "adapter %s seen on the wire" % stray_mac})
    for index, ip in enumerate(stray_ips):
        excerpts.append({"source": "stray-ip%d" % index, "line": "peer %s answered" % ip})
    registry_refs = {}
    for index, host in enumerate(UPSTREAM):
        ref = "%s/%s/%s@sha256:%s" % (host, _w(rng, 5), _w(rng, 5), _hex(rng, 64))
        registry_refs[host] = ref
        excerpts.append({"source": "reg%d" % index, "line": "pulled %s ok" % ref})

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
    inner = data_url("apiServer: %s\nnode: %s\nvip: %s\n# %s\n" % (api_url, unlisted, nested_addr, keep[3]),
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

    sensitive = {
        "cluster name": cluster_name,
        "infra id": infra_id,
        "api url": api_url,
        "mirror registry": mirror,
        "collected_by account": collected_by,
        "submitted_by account": submitted_by,
        "bundle id": bundle_id,
        "unlisted node": unlisted,
        "service dns host": svc_host,
        "internal host": plain_internal,
        "env secret": env_secret,
        "bearer token": bearer,
        "vault token": vault,
        "base64 secret": b64,
        "service account": service_account,
        "undeclared mac": stray_mac,
        "address with a port": port_addr,
        "address in reverse-DNS form": ptr_addr,
        "reverse-DNS octets of a cluster address": reverse_name(ptr_addr)[: -len(".in-addr.arpa")],
        "reverse-DNS octets of a node address": reverse_name(node_ips[0])[: -len(".in-addr.arpa")],
        "network address of a range": subnet,
        "low end of a range": range_lo,
        "high end of a range": range_hi,
    }
    for short, fqdn in node_names:
        sensitive["node %s" % short] = short
        sensitive["node fqdn %s" % short] = fqdn
    for index, ip in enumerate(node_ips):
        sensitive["node address %d" % index] = ip
    for index, mac in enumerate(node_macs):
        sensitive["mac %d" % index] = mac
    sensitive["address inside a gzipped payload"] = payload_addr
    sensitive["hostname inside a gzipped payload"] = payload_host
    sensitive["address inside a nested payload"] = nested_addr
    for index, ip in enumerate(stray_ips):
        sensitive["undeclared address in %s" % CLUSTER_PREFIXES[index]] = ip
    for host in (svc_host, plain_internal):
        sensitive["host label %s" % host.split(".")[0]] = host.split(".")[0]
    sensitive["dns suffix .mesa.internal"] = ".mesa.internal"
    sensitive["dns suffix %s" % suffix] = suffix

    preserved = {
        "upstream reference": upstream_ref,
        "sha512 digest": digest512,
        "digest of a mirrored image": mirror_digest,
        "version": version,
        "errata": errata,
        "issue url": issue_url,
        "absolute-path env value": key_path,
        "public address in reverse-DNS form": reverse_name(public),
        "public address with a port": "%s:443" % public,
        "public address": "via %s:53" % public,
        "public range": public_net,
    }
    for host, ref in registry_refs.items():
        preserved["upstream reference %s" % host] = ref
    preserved["gzipped payload with nothing sensitive (byte for byte)"] = clean_gz
    preserved["text payload with nothing sensitive (byte for byte)"] = clean_text
    preserved["non-text payload (byte for byte)"] = binary
    for index, word in enumerate(keep):
        preserved["non-sensitive text %d inside a sanitized payload" % index] = word

    truth = {
        "sensitive": sensitive,
        "preserved": preserved,
        "node_ips": node_ips,
        "port_addr": port_addr,
        "ptr_addr": ptr_addr,
        "subnet": subnet,
        "range": (range_lo, range_hi),
        "stray_ips": stray_ips,
        "node_macs": node_macs,
        "unlisted": unlisted,
        "payload_urls": [registries, chrony, ignition, inner, clean_gz, clean_text, binary],
    }
    return bundle, truth


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


class Service:
    """One isolated run of the submitted service.

    Each instance gets a private scratch directory that is removed on exit, so
    two processes cannot share state, and runs under -I -S so that packages
    installed for the verifier are not importable by submitted code.
    """

    def __init__(self, hashseed="0"):
        self.port = free_port()
        self.hashseed = hashseed
        self.root = None
        self.proc = None

    def __enter__(self):
        self.root = tempfile.mkdtemp(prefix="sluice-")
        script = os.path.join(self.root, "intake_server.py")
        shutil.copyfile(ARTIFACT, script)
        os.chmod(script, 0o555)

        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "PYTHONHASHSEED": self.hashseed,
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": self.root,
            "TMPDIR": self.root,
        }
        kwargs = {}
        uid = service_uid()
        if os.geteuid() == 0 and uid is not None:
            os.chown(script, uid, -1)
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
                time.sleep(0.2)
        raise AssertionError("the service never listened on port %d" % self.port)

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
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


@pytest.fixture(scope="module")
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


@pytest.mark.parametrize("seed", SEEDS)
def test_no_sensitive_value_survives(service, seed):
    bundle, truth = generate(seed)
    _, body = ok(service, bundle)
    case = json.loads(body)
    # Every string of the response, plus whatever its data-URL payloads decode to.
    text = expanded("\n".join(
        str(v) for key in ("items", "events", "log_excerpts") for entry in case[key] for v in entry.values()
    ))
    leaked = sorted(label for label, value in truth["sensitive"].items() if value in text)
    assert not leaked, (
        "seed %d: these reached the summary, in plain text or inside a data-URL payload: %r" % (seed, leaked)
    )


@pytest.mark.parametrize("seed", SEEDS)
def test_everything_else_survives(service, seed):
    bundle, truth = generate(seed)
    _, body = ok(service, bundle)
    case = json.loads(body)
    text = expanded("\n".join(
        str(v) for key in ("items", "events", "log_excerpts") for entry in case[key] for v in entry.values()
    ))
    missing = sorted(label for label, value in truth["preserved"].items() if value not in text)
    assert not missing, "seed %d: redaction destroyed %r" % (seed, missing)


def probe_lines(case, prefix):
    return {x["source"]: x["line"] for x in case["log_excerpts"] if x["source"].startswith(prefix)}


def test_placeholders_are_consistent_and_injective(service):
    """One value, one placeholder; two values, two placeholders.

    Each probe line contains exactly one value, so lines are compared whole:
    no assumption is made about placeholder syntax.
    """
    bundle, truth = generate(11)
    s = truth["sensitive"]
    probes = {
        "host": s["internal host"],
        "addr": truth["node_ips"][1],
        "addr2": truth["stray_ips"][3],
        "node-addr": truth["node_ips"][0],
        "mac": truth["node_macs"][0],
        "acct": s["collected_by account"],
        "unlisted": s["unlisted node"],
        "sa": s["service account"],
        "vault": s["vault token"],
    }
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
        assert first not in seen, "%s and %s collapsed onto the same placeholder %r" % (key, seen[first], first)
        seen[first] = key


def test_same_value_maps_identically_in_different_fields(service):
    """A value appearing in an event and in a log line gets one placeholder."""
    bundle, truth = generate(13)
    host = truth["sensitive"]["internal host"]
    bundle["evidence"]["events"].append(
        {"event_id": "EV-probe", "reason": "Probing", "namespace": "probes", "count": 1, "message": host}
    )
    bundle["evidence"]["log_excerpts"].append({"source": "p-cross", "line": host})
    case, _ = ok(service, bundle)
    event = [e for e in case["events"] if e["event_id"] == "EV-probe"][0]
    line = probe_lines(case, "p-cross")["p-cross"]
    assert event["message"] == line, (
        "the same host became %r in an event and %r in a log excerpt" % (event["message"], line)
    )


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
    port_addr, ptr_addr, subnet = truth["port_addr"], truth["ptr_addr"], truth["subnet"]
    node_addr = truth["node_ips"][0]
    lo, hi = truth["range"]
    plain = {"port": port_addr, "ptr": ptr_addr, "node": node_addr, "subnet": subnet, "lo": lo, "hi": hi}
    forms = {
        "cluster address with a port": ("%s:6443" % port_addr, "{port}:6443"),
        "node address with a port": ("%s:10250" % node_addr, "{node}:10250"),
        "cluster address in reverse-DNS form": (reverse_name(ptr_addr), "{ptr}.in-addr.arpa"),
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
    addr, node_addr, ptr_addr = truth["port_addr"], truth["node_ips"][0], truth["ptr_addr"]
    mac, unlisted = truth["node_macs"][0], truth["unlisted"]
    plain = {"addr": addr, "node": node_addr, "ptr": ptr_addr, "mac": mac, "unlisted": unlisted}
    rng = random.Random("payload-probe:%d" % seed)
    words = [_w(rng, 10) for _ in range(4)]

    def url(text, gz=None):
        raw = text.encode()
        if gz:
            raw = gzip.compress(raw, compresslevel=gz, mtime=1690000000 + seed)
        return "data:text/plain;base64," + b64enc(raw)

    text_src = "server=%s:6443\nnode=%s\nmac=%s\nkeep=%s\n" % (addr, unlisted, mac, words[0])
    text_want = "server={addr}:6443\nnode={unlisted}\nmac={mac}\nkeep=%s\n" % words[0]
    gz_src = "peer=%s\nkeep=%s\n" % (node_addr, words[1])
    gz_want = "peer={node}\nkeep=%s\n" % words[1]
    inner_src = "ptr=%s\nkeep=%s\n" % (reverse_name(ptr_addr), words[2])
    inner_want = "ptr={ptr}.in-addr.arpa\nkeep=%s\n" % words[2]
    outer_src = "files:\n- contents: %s\n- keep: %s\n" % (url(inner_src), words[3])

    excerpts = bundle["evidence"]["log_excerpts"]
    for key, value in plain.items():
        excerpts.append({"source": "e-plain-%s" % key, "line": "peer %s ok" % value})
    excerpts.append({"source": "e-text", "line": "wrote %s done" % url(text_src)})
    excerpts.append({"source": "e-gzip", "line": "wrote %s done" % url(gz_src, gz=6)})
    excerpts.append({"source": "e-nested", "line": "wrote %s done" % url(outer_src, gz=9)})
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
    bundle, _ = generate(23)
    _, first = ok(service, bundle)
    time.sleep(CLOCK_STEP)
    _, second = ok(service, bundle)
    assert first == second, "the same bundle produced two different responses"


def test_key_order_does_not_matter(service):
    bundle, _ = generate(29)
    _, plain = ok(service, bundle)
    time.sleep(CLOCK_STEP)
    _, shuffled = ok(service, reordered(bundle))
    assert plain == shuffled, "reordering keys changed the response"


def test_fresh_process_agrees(service):
    bundle, _ = generate(31)
    _, first = ok(service, bundle)
    time.sleep(CLOCK_STEP)
    with Service(hashseed="12345") as other:
        _, second = ok(other, bundle)
    assert first == second, "a restarted service produced a different response"


def test_fresh_process_agrees_on_reordered_input(service):
    """A restarted service receiving the reordered bundle first must agree."""
    bundle, _ = generate(37)
    _, first = ok(service, bundle)
    time.sleep(CLOCK_STEP)
    with Service(hashseed="999") as other:
        _, second = ok(other, reordered(bundle))
    assert first == second, "reordered input to a restarted service produced different bytes"


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


def test_service_user_cannot_read_verifier_assets():
    if os.geteuid() != 0 or service_uid() is None:
        pytest.skip("privilege separation only applies in the verifier image")
    probe = subprocess.run(
        [sys.executable, "-c", "open(%r).read()" % os.path.join(TESTS_DIR, "test_outputs.py")],
        user=SERVICE_USER,
        capture_output=True,
    )
    assert probe.returncode != 0, "the service account can read the verifier's own files"


def test_third_party_packages_are_not_importable():
    """The submitted service must run on the standard library alone."""
    probe = subprocess.run(
        [sys.executable, "-I", "-S", "-c", "import pytest"],
        capture_output=True,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    assert probe.returncode != 0, (
        "third-party packages are importable by submitted code; the service must be run isolated"
    )

"""Verifier for redact-cluster-support-bundle.

Every graded bundle is generated at grade time. Nothing is replayed from the
sample bundles shipped in the agent image: cluster names, node families,
addresses, credentials, resource ids, counts, reasons, namespaces, registries,
digests, versions and errata are all fresh, so a summary tuned to the samples
cannot pass. The generator records what it planted, and the assertions compare
the response against that record plus values derived from the stated contract
(case id, severity, schema). The agent's own service is executed and driven
over HTTP; nothing here reimplements redaction.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import pwd
import random
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

MAX_BYTES = 1048576
MAX_DEPTH = 64

CONDITION_WEIGHTS = {
    "EtcdMembersDegraded": 2.5,
    "APIServerUnavailable": 2.2,
    "NodeNotReady": 1.6,
    "CrashLoopBackOff": 1.2,
    "FailedMount": 1.0,
    "ImagePullBackOff": 0.8,
    "PodPending": 0.3,
}
DEFAULT_WEIGHT = 0.4
OUTAGE_MULTIPLIER = 1.5
NODE_DOWN_WEIGHT = 0.8
CEILING = 10.0

SUFFIXES = [".mesa.internal", ".svc.cluster.local", ".cluster.local"]
UPSTREAM = ["quay.io", "registry.redhat.io", "ghcr.io", "docker.io"]
CLUSTER_CIDRS = ["10.21", "10.44", "10.128", "172.30", "127.0"]


# ---------------------------------------------------------------------------
# Bundle generation
# ---------------------------------------------------------------------------


def _w(rng, n):
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(n))


def _alnum(rng, n):
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))


def _mac(rng):
    return ":".join("%02x" % rng.randrange(256) for _ in range(6))


def _ip(rng, cidr):
    if cidr == "127.0":
        return "127.%d.%d.%d" % (rng.randrange(1, 254), rng.randrange(1, 254), rng.randrange(1, 254))
    a, b = cidr.split(".")
    return "%s.%s.%d.%d" % (a, b, rng.randrange(1, 254), rng.randrange(1, 254))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def expected_case_id(evidence):
    return "SL-%s" % hashlib.sha256(canonical(evidence).encode()).hexdigest()[:16]


def expected_severity(resources, nodes):
    total = 0.0
    for res in resources:
        weight = CONDITION_WEIGHTS.get(res["condition"], DEFAULT_WEIGHT)
        rep = res.get("replicas") or {}
        if rep.get("desired", 0) > 0 and rep.get("ready", 0) == 0:
            weight *= OUTAGE_MULTIPLIER
        total += weight
    for node in nodes:
        for cond in node.get("conditions") or []:
            if cond.get("type") == "Ready" and cond.get("status") != "True":
                total += NODE_DOWN_WEIGHT
    return round(min(total, CEILING), 2)


def generate(seed):
    """Build a fresh bundle plus a record of what it contains.

    Every sensitive class is planted in at least one field the contract
    requires the response to keep, and every preserved class likewise.
    """
    rng = random.Random("bundle:%d" % seed)

    cluster_name = "%s-%s" % (_w(rng, 4), _w(rng, 5))
    domain = _w(rng, 6)
    suffix = SUFFIXES[seed % len(SUFFIXES)]
    node_prefix = rng.choice([_w(rng, 5), "%s-%s" % (_w(rng, 4), _w(rng, 4))])
    infra_id = "%s-%s" % (cluster_name, _alnum(rng, 5))
    api_host = "api.%s.mesa.internal" % cluster_name
    # A mirror host that is deliberately not under an internal suffix.
    mirror = "%s.example.net:5000" % _w(rng, 7)
    collected_by = "%s\\%s.%s" % (domain.upper(), _w(rng, 2), _w(rng, 6))
    submitted_by = "%s-ops" % _w(rng, 6)
    service_account = "system:serviceaccount:%s:%s" % (_w(rng, 6), _w(rng, 6))

    node_names, node_ips, node_macs, nodes = [], [], [], []
    for index in range(rng.randrange(2, 5)):
        short = "%s-%02d" % (node_prefix, 10 + index)
        fqdn = "%s.%s.mesa.internal" % (short, cluster_name)
        # One node address deliberately sits outside the configured ranges;
        # the contract makes any declared node internal_ip sensitive.
        cidr = CLUSTER_CIDRS[index % len(CLUSTER_CIDRS)] if index else "192.168"
        ip = _ip(rng, cidr) if index else "192.168.%d.%d" % (rng.randrange(1, 254), rng.randrange(1, 254))
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
                "conditions": [
                    {"type": "Ready", "status": "True" if index % 2 else "False", "message": "kubelet on %s" % fqdn}
                ],
            }
        )
    unlisted = "%s-%02d" % (node_prefix, 70 + seed % 20)

    namespaces = [_w(rng, 7) for _ in range(3)]
    reasons = ["%s%s" % (_w(rng, 4).capitalize(), _w(rng, 5).capitalize()) for _ in range(3)]
    conditions = list(CONDITION_WEIGHTS)
    resources = []
    for index in range(rng.randrange(5, 9)):
        resources.append(
            {
                "resource_id": "RES-%s" % _alnum(rng, 6),
                "kind": rng.choice(["Pod", "Deployment", "DaemonSet", "StatefulSet"]),
                "namespace": namespaces[index % len(namespaces)],
                "name": "%s-%s" % (_w(rng, 5), node_names[index % len(node_names)][0]),
                "condition": conditions[index % len(conditions)],
                "node": node_names[index % len(node_names)][1],
                "replicas": {"desired": rng.randrange(1, 9), "ready": 0 if index % 2 else 2},
                "spec": {
                    "containers": [
                        {
                            "name": _w(rng, 5),
                            "image": "%s/%s/%s@sha256:%s"
                            % (UPSTREAM[index % len(UPSTREAM)], _w(rng, 5), _w(rng, 6), _alnum(rng, 64).lower()),
                            "env": [{"name": "APP_SECRET", "value": _alnum(rng, 18)}],
                        }
                    ]
                },
            }
        )
    # One duplicate through an owner chain, and a distinct resource sharing
    # kind/namespace/name with another so that resource_id identity is forced.
    resources[1] = dict(resources[1], owner=dict(resources[0]))
    twin = dict(resources[2])
    twin["resource_id"] = "RES-%s" % _alnum(rng, 6)
    resources.append(twin)

    env_secret = resources[0]["spec"]["containers"][0]["env"][0]["value"]
    bearer = _alnum(rng, 22)
    keyed = _alnum(rng, 16)
    userpass = "%s:%s" % (_w(rng, 5), _alnum(rng, 10))
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
    digest512 = "sha512:%s" % _alnum(rng, 128).lower()
    upstream_ref = "%s/%s/%s@%s" % (UPSTREAM[seed % len(UPSTREAM)], _w(rng, 5), _w(rng, 5), digest512)

    events = [
        {
            "event_id": "EV-%s" % _alnum(rng, 5),
            "reason": reasons[0],
            "namespace": namespaces[0],
            "message": "pull from %s failed for user %s; seen from %s" % (mirror, userpass, node_macs[0]),
        },
        {
            "event_id": "EV-%s" % _alnum(rng, 5),
            "reason": reasons[1],
            "namespace": namespaces[1],
            "message": "probe to %s (%s) failed; %s is healthy" % (svc_host, node_ips[0], upstream_ref),
        },
    ]
    excerpts = [
        {"source": _w(rng, 6), "line": "collecting cluster %s id %s via %s" % (cluster_name, infra_id, api_host)},
        {"source": _w(rng, 6), "line": "peer %s unreachable from %s" % (unlisted, node_names[0][0])},
        {"source": _w(rng, 6), "line": "Authorization: Bearer %s to %s" % (bearer, plain_internal)},
        {"source": _w(rng, 6), "line": "token=%s user %s vault %s blob %s" % (keyed, userpass, vault, b64)},
        {"source": _w(rng, 6), "line": "submitted by %s as %s collected by %s" % (submitted_by, service_account, collected_by)},
        {"source": _w(rng, 6), "line": "running %s version %s; see %s and %s" % (upstream_ref, version, errata, issue_url)},
        {"source": _w(rng, 6), "line": "env secret %s on %s" % (env_secret, node_ips[-1])},
    ]
    for index, ip in enumerate(node_ips):
        excerpts.append({"source": "addr%d" % index, "line": "endpoint %s and %s" % (ip, node_macs[index])})
    stray_mac = _mac(rng)
    stray_ips = [_ip(rng, cidr) for cidr in CLUSTER_CIDRS]
    excerpts.append({"source": "stray-mac", "line": "adapter %s seen on the wire" % stray_mac})
    for index, ip in enumerate(stray_ips):
        excerpts.append({"source": "stray-ip%d" % index, "line": "peer %s answered" % ip})
    registry_refs = {}
    for index, host in enumerate(UPSTREAM):
        ref = "%s/%s/%s@sha256:%s" % (host, _w(rng, 5), _w(rng, 5), _alnum(rng, 64).lower())
        registry_refs[host] = ref
        excerpts.append({"source": "reg%d" % index, "line": "pulled %s ok" % ref})

    evidence = {"resources": resources, "nodes": nodes, "events": events, "log_excerpts": excerpts}
    bundle = {
        "bundle_id": "SB-%s" % _alnum(rng, 8),
        "submitted_by": submitted_by,
        "severity_override": round(rng.uniform(0, 10), 1),
        "cluster": {
            "name": cluster_name,
            "version": version,
            "api_url": "https://%s:6443" % api_host,
            "infra_id": infra_id,
            "mirror_registry": mirror,
            "collected_by": collected_by,
        },
        "evidence": evidence,
    }

    unique = {}
    for res in resources:
        unique.setdefault(res["resource_id"], res)
    sensitive = {
        "cluster name": cluster_name,
        "infra id": infra_id,
        "api host": api_host,
        "mirror registry": mirror,
        "collected_by account": collected_by,
        "submitted_by account": submitted_by,
        "bundle id": bundle["bundle_id"],
        "unlisted node": unlisted,
        "service dns host": svc_host,
        "internal host": plain_internal,
        "env secret": env_secret,
        "bearer token": bearer,
        "keyed secret": keyed,
        "user credential": userpass,
        "vault token": vault,
        "base64 secret": b64,
    }
    for short, fqdn in node_names:
        sensitive["node %s" % short] = short
        sensitive["node fqdn %s" % short] = fqdn
    for index, ip in enumerate(node_ips):
        sensitive["node address %d" % index] = ip
    for index, mac in enumerate(node_macs):
        sensitive["mac %d" % index] = mac
    sensitive["service account"] = service_account
    sensitive["undeclared mac"] = stray_mac
    for index, ip in enumerate(stray_ips):
        sensitive["undeclared address %s" % CLUSTER_CIDRS[index]] = stray_ips[index]
    for host in (svc_host, plain_internal, api_host):
        sensitive["host label %s" % host.split(".")[0]] = host.split(".")[0]
    for suf in SUFFIXES:
        if suf in svc_host or suf in plain_internal or suf in api_host:
            sensitive["dns suffix %s" % suf] = suf

    preserved = {
        "upstream reference": upstream_ref,
        "sha512 digest": digest512,
        "version": version,
        "errata": errata,
        "issue url": issue_url,
    }
    for res in unique.values():
        preserved["namespace %s" % res["namespace"]] = res["namespace"]
        preserved["condition %s" % res["condition"]] = res["condition"]
    for event in events:
        preserved["reason %s" % event["reason"]] = event["reason"]
    for host, ref in registry_refs.items():
        preserved["upstream reference %s" % host] = ref

    truth = {
        "sensitive": sensitive,
        "preserved": preserved,
        "case_id": expected_case_id(evidence),
        "severity": expected_severity(list(unique.values()), nodes),
        "resource_ids": sorted(unique),
        "namespaces": sorted({r["namespace"] for r in unique.values()}),
        "event_ids": [e["event_id"] for e in events],
        "sources": [x["source"] for x in excerpts],
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

    def __init__(self, host="127.0.0.1", hashseed="0"):
        self.host = host
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
            [sys.executable, "-I", "-S", script, "--host", self.host, "--port", str(self.port)],
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
                    "the service exited immediately (rc=%s); it must start with --host/--port "
                    "using only the standard library.\n%s" % (self.proc.returncode, err)
                )
            try:
                with socket.create_connection((self.host, self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.2)
        raise AssertionError("the service never listened on %s:%d" % (self.host, self.port))

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

    def get(self, path):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=60)
        try:
            conn.request("GET", path)
            r = conn.getresponse()
            return r.status, r.read()
        finally:
            conn.close()

    def post(self, bundle):
        return self.raw(json.dumps(bundle).encode())

    def raw(self, body, path="/intake"):
        head = (
            "POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n" % (path, self.host, self.port, len(body))
        ).encode("ascii")
        sock = socket.create_connection((self.host, self.port), timeout=90)
        chunks = []
        try:
            sock.sendall(head)
            view, sent = memoryview(body), 0
            try:
                while sent < len(body):
                    sent += sock.send(view[sent : sent + 65536])
            except (BrokenPipeError, ConnectionResetError):
                pass
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            total = 0
            while total < 4_000_000:
                try:
                    data = sock.recv(65536)
                except (ConnectionResetError, socket.timeout):
                    break
                if not data:
                    break
                chunks.append(data)
                total += len(data)
        finally:
            sock.close()
        response = b"".join(chunks)
        assert response, "the service closed the connection without responding"
        head_bytes, _, tail = response.partition(b"\r\n\r\n")
        status = head_bytes.split(b"\r\n", 1)[0].split()[1]
        return int(status), tail


@pytest.fixture(scope="module")
def service():
    assert os.path.isfile(ARTIFACT), "%s is missing from the collected artifacts" % ARTIFACT
    with Service() as running:
        yield running


def ok(service_, bundle):
    status, body = service_.post(bundle)
    assert status == 200, "a valid bundle must be accepted; got %d: %r" % (status, body[:300])
    return json.loads(body), body


def reject(status, body, label):
    text = body.decode("utf-8", "replace")
    assert 400 <= status < 500, "%s must be refused with 4xx; got %d" % (label, status)
    payload = json.loads(text)
    assert set(payload) == {"error"} and isinstance(payload["error"], str), (
        "%s: an error body must be exactly {\"error\": \"...\"}; got %r" % (label, text[:300])
    )


# ---------------------------------------------------------------------------
# Schema and derived values
# ---------------------------------------------------------------------------


SEEDS = [3, 17, 41]


@pytest.mark.parametrize("seed", SEEDS)
def test_response_schema(service, seed):
    """Exactly the required keys, with the required types."""
    bundle, truth = generate(seed)
    case, _ = ok(service, bundle)
    assert set(case) == {"case_id", "severity", "items", "events", "log_excerpts", "namespaces"}, (
        "unexpected response keys: %r" % sorted(case)
    )
    assert isinstance(case["case_id"], str) and case["case_id"], "case_id must be a non-empty string"
    assert isinstance(case["severity"], (int, float)), "severity must be a number"
    for key in ("items", "events", "log_excerpts", "namespaces"):
        assert isinstance(case[key], list), "%s must be a list" % key
    for item in case["items"]:
        assert set(item) >= {"resource_id", "kind", "namespace", "name", "condition", "node"}
    assert all(isinstance(n, str) for n in case["namespaces"]), "namespaces must all be strings"


def test_empty_collections_are_still_reported(service):
    """A bundle with nothing in it still returns every required key."""
    case, _ = ok(service, {"bundle_id": "SB-empty", "evidence": {}})
    assert set(case) == {"case_id", "severity", "items", "events", "log_excerpts", "namespaces"}
    assert case["items"] == [] and case["events"] == [] and case["log_excerpts"] == []
    assert case["namespaces"] == [] and isinstance(case["case_id"], str)


@pytest.mark.parametrize("seed", SEEDS)
def test_case_id_matches_the_defined_formula(service, seed):
    """case_id is the stated digest of the evidence, not a per-process value."""
    bundle, truth = generate(seed)
    case, _ = ok(service, bundle)
    assert case["case_id"] == truth["case_id"], (
        "case_id %r does not match the contract's SHA-256 of the canonical evidence (%r)"
        % (case["case_id"], truth["case_id"])
    )


@pytest.mark.parametrize("seed", SEEDS)
def test_severity_matches_the_weights(service, seed):
    bundle, truth = generate(seed)
    case, _ = ok(service, bundle)
    assert case["severity"] == pytest.approx(truth["severity"], abs=0.01), (
        "severity %r does not match the weighted evidence value %r" % (case["severity"], truth["severity"])
    )


def test_unknown_condition_uses_the_default_weight(service):
    """An unlisted condition scores the default weight, not zero."""
    res = {
        "resource_id": "R1", "kind": "Pod", "namespace": "ns", "name": "n",
        "condition": "SomethingNobodyListed", "replicas": {"desired": 1, "ready": 1},
    }
    case, _ = ok(service, {"bundle_id": "B", "evidence": {"resources": [res]}})
    assert case["severity"] == pytest.approx(DEFAULT_WEIGHT, abs=0.01), (
        "an unlisted condition must score the default weight %.2f, got %r" % (DEFAULT_WEIGHT, case["severity"])
    )


def test_severity_is_capped(service):
    """Enough degraded resources must saturate at the ceiling."""
    resources = [
        {"resource_id": "R%d" % i, "kind": "Pod", "namespace": "ns", "name": "n%d" % i,
         "condition": "EtcdMembersDegraded", "replicas": {"desired": 3, "ready": 1}}
        for i in range(6)
    ]
    case, _ = ok(service, {"bundle_id": "B", "evidence": {"resources": resources}})
    assert case["severity"] == pytest.approx(CEILING, abs=0.01), (
        "severity must be capped at %.1f, got %r" % (CEILING, case["severity"])
    )


# ---------------------------------------------------------------------------
# Redaction and preservation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_no_generated_identifier_survives(service, seed):
    bundle, truth = generate(seed)
    _, body = ok(service, bundle)
    text = body.decode("utf-8", "replace")
    leaked = sorted(label for label, value in truth["sensitive"].items() if value in text)
    assert not leaked, "seed %d: these reached the summary: %r" % (seed, leaked)


@pytest.mark.parametrize("seed", SEEDS)
def test_preserved_values_survive(service, seed):
    bundle, truth = generate(seed)
    _, body = ok(service, bundle)
    text = body.decode("utf-8", "replace")
    missing = sorted(label for label, value in truth["preserved"].items() if value not in text)
    assert not missing, "seed %d: redaction destroyed %r" % (seed, missing)


def test_severity_override_never_appears(service):
    """The submitted severity is ignored and must not be echoed anywhere."""
    bundle, truth = generate(5)
    bundle["severity_override"] = 9.875
    case, body = ok(service, bundle)
    assert case["severity"] == pytest.approx(truth["severity"], abs=0.01)
    assert "9.875" not in body.decode("utf-8", "replace"), "severity_override was echoed in the response"


@pytest.mark.parametrize("override", [None, 0.0, 1.0, 10.0, -3.0, "high"])
def test_override_does_not_change_the_response(service, override):
    bundle, _ = generate(7)
    baseline = dict(bundle)
    baseline.pop("severity_override", None)
    _, want = ok(service, baseline)
    if override is None:
        bundle.pop("severity_override", None)
    else:
        bundle["severity_override"] = override
    _, got = ok(service, bundle)
    assert got == want, "severity_override=%r changed the response" % override


def test_placeholders_are_consistent_and_injective(service):
    """One value, one placeholder; two values, two placeholders.

    Each probe record contains exactly one value, so records are compared
    whole: no assumption is made about placeholder syntax.
    """
    bundle, truth = generate(11)
    probes = {
        "host": truth["sensitive"]["internal host"],
        "addr": truth["sensitive"]["node address 1"],
        "addr2": truth["sensitive"]["undeclared address 172.30"],
        "mac": truth["sensitive"]["mac 0"],
        "acct": truth["sensitive"]["collected_by account"],
        "node": truth["sensitive"]["unlisted node"],
    }
    excerpts = bundle["evidence"]["log_excerpts"]
    for key, value in probes.items():
        excerpts.append({"source": "p-%s-1" % key, "line": value})
        excerpts.append({"source": "p-%s-2" % key, "line": value})
    case, _ = ok(service, bundle)
    lines = {x["source"]: x["line"] for x in case["log_excerpts"]}

    seen = {}
    for key in probes:
        first, second = "p-%s-1" % key, "p-%s-2" % key
        assert first in lines and second in lines, "log excerpts must be reported (%s)" % key
        assert lines[first] == lines[second], (
            "%s produced two different placeholders: %r vs %r" % (key, lines[first], lines[second])
        )
        assert probes[key] not in lines[first], "%s: placeholder still contains the value" % key
        assert lines[first] not in seen, (
            "%s and %s collapsed onto the same placeholder %r" % (key, seen[lines[first]], lines[first])
        )
        seen[lines[first]] = key


def test_same_value_maps_identically_in_different_fields(service):
    """A value appearing in an event and in a log line gets one placeholder."""
    bundle, truth = generate(13)
    host = truth["sensitive"]["internal host"]
    bundle["evidence"]["events"].append(
        {"event_id": "EV-probe", "reason": "Probing", "namespace": "probes", "message": host}
    )
    bundle["evidence"]["log_excerpts"].append({"source": "p-cross", "line": host})
    case, _ = ok(service, bundle)
    event = [e for e in case["events"] if e["event_id"] == "EV-probe"][0]
    line = [x for x in case["log_excerpts"] if x["source"] == "p-cross"][0]["line"]
    assert event["message"] == line, (
        "the same host became %r in an event and %r in a log excerpt" % (event["message"], line)
    )


# ---------------------------------------------------------------------------
# Rejection
# ---------------------------------------------------------------------------


def deep_body(depth):
    """JSON whose maximum nesting is exactly `depth`."""
    inner = '{"bundle_id":"d","evidence":{}}'          # two levels on its own
    wrap = depth - 2
    return ('{"pad":' * wrap + inner + "}" * wrap).encode()


def test_depth_at_the_limit_is_accepted(service):
    status, body = service.raw(deep_body(MAX_DEPTH))
    assert status == 200, "nesting of exactly %d must be accepted; got %d" % (MAX_DEPTH, status)


def test_depth_over_the_limit_is_refused(service):
    status, body = service.raw(deep_body(MAX_DEPTH + 1))
    reject(status, body, "a bundle nested %d deep" % (MAX_DEPTH + 1))


def test_body_just_under_the_limit_is_accepted(service):
    bundle = {"bundle_id": "B", "pad": "", "evidence": {}}
    pad = MAX_BYTES - len(json.dumps(bundle).encode()) - 16
    bundle["pad"] = "A" * pad
    body = json.dumps(bundle).encode()
    assert len(body) <= MAX_BYTES
    status, _ = service.raw(body)
    assert status == 200, "a body of %d bytes is within the limit; got %d" % (len(body), status)


def test_body_over_the_limit_is_refused(service):
    bundle = {"bundle_id": "B", "pad": "A" * (MAX_BYTES + 1000), "evidence": {}}
    status, body = service.raw(json.dumps(bundle).encode())
    assert status == 413, "a body over %d bytes must get 413; got %d" % (MAX_BYTES, status)
    reject(status, body, "an oversized bundle")


@pytest.mark.parametrize(
    "label,payload",
    [
        ("truncated JSON", b'{"bundle_id": "x", "evidence": {'),
        ("a JSON array", b"[1, 2, 3]"),
        ("a NaN literal", b'{"evidence":{"resources":[{"resource_id":"r","kind":"Pod","namespace":"n",'
                          b'"name":"n","condition":"PodPending","replicas":{"desired":NaN}}]}}'),
        ("a non-object evidence", b'{"evidence": "nope"}'),
        ("a non-list events", b'{"evidence": {"events": "nope"}}'),
        ("a resource without resource_id", b'{"evidence":{"resources":[{"kind":"Pod","namespace":"n",'
                                           b'"name":"n","condition":"PodPending"}]}}'),
        ("a resource with a numeric namespace", b'{"evidence":{"resources":[{"resource_id":"r","kind":"Pod",'
                                                b'"namespace":7,"name":"n","condition":"PodPending"}]}}'),
        ("a log excerpt without source", b'{"evidence":{"log_excerpts":[{"line":"x"}]}}'),
        ("a log excerpt without line", b'{"evidence":{"log_excerpts":[{"source":"x"}]}}'),
        ("an event without reason", b'{"evidence":{"events":[{"event_id":"e","namespace":"n","message":"m"}]}}'),
    ],
)
def test_bad_bundles_are_refused(service, label, payload):
    status, body = service.raw(payload)
    reject(status, body, label)


def test_error_bodies_carry_nothing_else(service):
    """Error responses must not disclose paths or configuration."""
    status, body = service.raw(b"{not json")
    reject(status, body, "a malformed bundle")


def test_service_survives_rejections(service):
    service.raw(b"{not json")
    bundle, truth = generate(19)
    case, _ = ok(service, bundle)
    assert case["case_id"] == truth["case_id"]


def test_healthz_exposes_nothing_else(service):
    status, body = service.get("/healthz")
    if status == 404:
        pytest.skip("service does not expose /healthz")
    payload = json.loads(body)
    assert set(payload) <= {"status", "service", "version"}, (
        "/healthz may only return status, service and version; got %r" % sorted(payload)
    )


# ---------------------------------------------------------------------------
# Resource identity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_each_resource_reported_once(service, seed):
    bundle, truth = generate(seed)
    case, _ = ok(service, bundle)
    ids = [i["resource_id"] for i in case["items"]]
    assert sorted(ids) == truth["resource_ids"], (
        "expected one item per distinct resource_id %r, got %r" % (truth["resource_ids"], sorted(ids))
    )
    assert sorted(case["namespaces"]) == truth["namespaces"]


def test_distinct_ids_sharing_a_name_are_not_merged(service):
    """Identity is resource_id, not kind/namespace/name."""
    base = {"kind": "Pod", "namespace": "ns", "name": "api", "condition": "PodPending"}
    bundle = {
        "bundle_id": "B",
        "evidence": {"resources": [dict(base, resource_id="R1"), dict(base, resource_id="R2")]},
    }
    case, _ = ok(service, bundle)
    assert sorted(i["resource_id"] for i in case["items"]) == ["R1", "R2"], (
        "two distinct resource_ids were collapsed: %r" % case["items"]
    )


def test_duplicate_id_resolution_is_canonical(service):
    """Records sharing an id, differing only by name, resolve the same way."""
    a = {"resource_id": "R", "kind": "Pod", "namespace": "ns", "name": "aa", "condition": "PodPending"}
    b = {"resource_id": "R", "kind": "Pod", "namespace": "ns", "name": "bb", "condition": "PodPending"}
    first, _ = ok(service, {"bundle_id": "B", "evidence": {"one": [a], "two": [b]}})
    second, _ = ok(service, {"bundle_id": "B", "evidence": {"two": [b], "one": [a]}})
    assert len(first["items"]) == 1 and len(second["items"]) == 1
    assert first["items"][0]["name"] == second["items"][0]["name"], (
        "duplicate resolution depends on key order: %r vs %r" % (first["items"], second["items"])
    )


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def reordered(value):
    return json.loads(json.dumps(value, sort_keys=True))


def test_repeat_is_byte_identical(service):
    bundle, _ = generate(23)
    _, first = ok(service, bundle)
    _, second = ok(service, bundle)
    assert first == second


def test_key_order_does_not_matter(service):
    bundle, _ = generate(29)
    _, plain = ok(service, bundle)
    _, sorted_keys = ok(service, reordered(bundle))
    assert plain == sorted_keys, "reordering keys changed the response"


def test_fresh_process_agrees(service):
    bundle, _ = generate(31)
    _, first = ok(service, bundle)
    with Service(hashseed="12345") as other:
        _, second = ok(other, bundle)
    assert first == second, "a second process produced a different response"


def test_fresh_process_agrees_on_reordered_input(service):
    """A restarted process receiving the reordered bundle first must agree."""
    bundle, _ = generate(37)
    _, first = ok(service, bundle)
    with Service(hashseed="999") as other:
        _, second = ok(other, reordered(bundle))
    assert first == second, "reordered input to a fresh process produced different bytes"


# ---------------------------------------------------------------------------
# Interface and isolation
# ---------------------------------------------------------------------------


def test_host_option_is_honoured():
    """--host must actually bind where it is told."""
    with Service(host="127.0.0.2") as other:
        bundle, truth = generate(43)
        case, _ = ok(other, bundle)
        assert case["case_id"] == truth["case_id"]


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
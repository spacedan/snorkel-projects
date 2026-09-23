The intake service at `/app/sluice/intake_server.py` turns a collected cluster support bundle into the case summary we are cleared to send to the vendor. Right now it copies the whole bundle into its response, so container env vars, mirror registry credentials and a Vault token sitting in a log line all leave with it. It accepts a bundle of any size, returns stack traces on malformed or deeply nested input, and takes case severity from a field the submitter fills in instead of working it out from the evidence.

Fix it. Keep the service at that path, keep the `--host` and `--port` options working, and keep accepting a bundle as `POST /intake`. Sample bundles are in `/app/fixtures/`. Standard library only.

**Every string in the response must be sanitized**, except the fields listed under "always preserved" below. Sanitizing means replacing sensitive values with placeholders. The placeholder format is yours to choose, with two rules: a placeholder must not contain the value it replaced, and within one response the mapping must be one-to-one — the same value always becomes the same placeholder, and two different values never become the same one.

Sensitive values are exactly these, wherever they occur in a string, including inside free text and inside larger tokens:

- the value of any of `submitted_by`, `bundle_id`, `cluster.name`, `cluster.infra_id`, `cluster.api_url`, `cluster.mirror_registry`, `cluster.collected_by`, and for each entry of `evidence.nodes`, its `name`, `internal_ip` and `mac`
- the first DNS label of any `evidence.nodes[].name` (its short name)
- any `<prefix>-<digits>` token, where `<prefix>` is a node short name with its trailing `-<digits>` removed — this covers nodes the bundle does not list
- any hostname ending in `.mesa.internal`, `.svc.cluster.local` or `.cluster.local`, including the suffix itself
- any IPv4 address inside `10.21.0.0/16`, `10.44.0.0/16`, `10.128.0.0/14`, `172.30.0.0/16` or `127.0.0.0/8`, or equal to any `evidence.nodes[].internal_ip`
- any MAC address, written as six colon-separated hex pairs
- any `system:serviceaccount:<namespace>:<name>`, and any `<DOMAIN>\<user>`
- credential material, which for this service means exactly: the value of a container env var whose name contains `PASS`, `SECRET`, `TOKEN`, `CRED`, `AUTH` or `KEY` and whose value is not an absolute path; a `Bearer <token>`; the value after `password`, `passwd`, `token`, `secret` or `apikey` followed by `:` or `=`; a `<user>:<password>` pair following the word `user`; a string starting `hvs.`; and a base64 string starting `eyJ`

**Always preserved, byte for byte:** the `reason` and `namespace` of every event, the `namespace` and `condition` of every resource, the `source` of every log excerpt, and every `resource_id`. Never redact an image reference whose registry host is `quay.io`, `registry.redhat.io`, `ghcr.io` or `docker.io`; a digest of the form `<algorithm>:<hex>`; a version string; an errata identifier like `RHBA-2026:4471`; or a URL whose host is not one of the internal suffixes above.

**Rejecting bad bundles.** A request body over 1048576 bytes gets `413`. A bundle nested deeper than 64 levels gets `400`. So does a body that is not valid JSON, is not a JSON object, contains `NaN` or `Infinity`, or does not match the input shape: `evidence` must be an object; `resources`, `nodes`, `events` and `log_excerpts`, where present, must be lists of objects; every resource needs a string `resource_id`, `kind`, `namespace`, `name` and `condition`; every node a string `name`; every event a string `event_id`, `reason`, `namespace` and `message`; every log excerpt a string `source` and `line`. An error response body must be exactly `{"error": "<message>"}` and nothing else.

**Severity** is computed from the evidence with the weights already in the service, including the default weight for an unlisted condition and the ceiling. The submitted `severity_override` is ignored and must not appear anywhere in the response.

**Resources** are identified by `resource_id`. Owner chains repeat them; report each once. When two records share an id, keep the one with more keys, and if they tie, the one whose JSON with sorted keys sorts first.

**Determinism.** `case_id` is `SL-` followed by the first 16 hex characters of the SHA-256 of `evidence` serialized as JSON with sorted keys and no whitespace. Equivalent bundles — same content, keys in any order — must produce byte-identical responses, in the same process and in a fresh one.

**The response** is a JSON object with exactly these keys, and they are always present even when a collection is empty:

- `case_id` — string
- `severity` — number
- `items` — one object per distinct resource, each with its `resource_id`, `kind`, `namespace`, `name`, `condition` and `node`
- `events` — one object per event, each keeping its `event_id`, `reason`, `namespace` and `message`
- `log_excerpts` — one object per excerpt, each keeping its `source` and `line`
- `namespaces` — sorted list of the distinct resource namespaces, all strings

If you keep `/healthz`, its response may contain only `status`, `service` and `version`.
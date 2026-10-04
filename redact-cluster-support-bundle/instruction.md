The intake service at `/app/sluice/intake_server.py` turns a collected cluster support bundle into the case summary we're cleared to send to the vendor. Right now it copies the whole bundle into its response, so node addresses, internal hostnames, container secrets and a Vault token sitting in a log line all leave with it, and two runs over the same bundle don't produce the same summary.

Fix it. Keep the service at that path, keep the `--port` option working, and keep accepting a bundle as `POST /intake`. Sample bundles are in `/app/fixtures/`; every bundle the service gets has the same shape as those. Standard library only.

The response is a JSON object with exactly three keys: `items` has one object per entry in `evidence.resources`, with just its `resource_id`, `kind`, `namespace`, `name`, `condition` and `node`; `events` has one object per entry in `evidence.events`, with just its `event_id`, `reason`, `namespace` and `message`; `log_excerpts` has one object per entry in `evidence.log_excerpts`, with just its `source` and `line`. Keep each list in bundle order.

`resource_id`, `kind`, `namespace`, `condition`, `event_id`, `reason` and `source` are copied as they are. In `name`, `node`, `message` and `line`, replace every sensitive value with a placeholder and leave all other text exactly as it was, so upstream image references, digests, versions, errata IDs and public URLs come through untouched. Placeholder format is up to you, but a placeholder can't contain the value it replaced, and within one response the same value always gets the same placeholder and two different values never share one.

These are the sensitive values, wherever they appear in those fields:

- the value of `submitted_by`, `bundle_id`, `cluster.name`, `cluster.infra_id`, `cluster.api_url`, `cluster.mirror_registry` and `cluster.collected_by`, and each node's `name`, `internal_ip` and `mac`
- each node's short name (the first label of its `name`), and any `<prefix>-<digits>` where `<prefix>` is a short name with its trailing `-<digits>` removed, which catches nodes the bundle doesn't list
- any hostname ending in `.mesa.internal`, `.svc.cluster.local` or `.cluster.local`, suffix included
- any IPv4 address in `10.21.0.0/16`, `10.44.0.0/16`, `10.128.0.0/14`, `172.30.0.0/16` or `127.0.0.0/8`, or equal to a node's `internal_ip`
- any MAC address written as six colon-separated hex pairs
- any `system:serviceaccount:<namespace>:<name>`
- the value of a container env var whose name contains `PASS`, `SECRET`, `TOKEN`, `CRED`, `AUTH` or `KEY`, unless the value is an absolute path; the token after `Bearer `; any string starting `hvs.`; and any base64 string starting `eyJ`

An address counts however it's written: on its own, with a port (`10.21.3.4:6443`), as the network address or either end of a range (`10.128.0.0/14`, `10.21.4.10-10.21.4.50`), or as a reverse-DNS name (`4.3.21.10.in-addr.arpa` is 10.21.3.4). Replace only the address, keep the port, prefix length, hyphen or `.in-addr.arpa` around it, and use the same placeholder that address gets when it's written plainly. An address that isn't sensitive stays as it is in every one of those forms.

Messages and log lines can also carry file contents as a data URL, `data:<type>;base64,<payload>`. The payload is base64, with gzip underneath when the decoded bytes start with the gzip magic number. When what it holds is UTF-8 text, sanitize that text by these same rules, including any data URLs inside it and with the same placeholders as the rest of the response, then encode it again the way it came: gzip if it was gzipped, then base64. A payload that isn't UTF-8 text, or that has nothing sensitive in it, stays byte for byte as it was.

The same bundle, with its keys in any order, has to produce a byte-identical response every time, including after the service restarts.

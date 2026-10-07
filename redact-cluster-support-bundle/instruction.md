There is an intake service at `/app/sluice/intake_server.py` which turns a collected Kubernetes cluster support bundle into the case summary that we're cleared to send to the vendor. Right now it copies the whole bundle into its response, so everything that with sensitive identifying information leaves with it, and two runs over the same bundle don't produce the same summary.

Fix it. Keep the service at that path, keep the `--port` option working, and keep accepting a bundle as `POST /intake`. Use the standard library only.

Until now our release desk has cleaned these summaries by hand. The directory `/app/fixtures/` has three collected bundles, and `/app/fixtures/cleared/` has the summary that our team cleared for each of them. Those are the reference for what the service returns: the same shape, the same kinds of thing replaced, and everything else left exactly as it was. The service has to do that for any bundle shaped like these, not only for these three. The address ranges, DNS suffixes and env-var hints our team works from are the constants at the top of the service.

The included samples cover every kind of thing our team replaces and every kind it leaves alone, including values written in more than one form and file contents embedded in a line.

The response is a JSON object with exactly three keys. 'items' has one object per entry in 'evidence.resources', with only its 'resource_id', 'kind', 'namespace', 'name', 'condition' and 'node'. 'events' has one per entry in 'evidence.events', with only 'event_id', 'reason', 'namespace' and 'message'. 'log_excerpts' has one per entry in 'evidence.log_excerpts', with only 'source' and 'line'. Each list keeps the bundle's order, and only 'name', 'node', 'message' and 'line' are ever changed.

Our team's placeholder text isn't significant, so the format is up to you. What has to hold is that a placeholder doesn't contain the value it replaced, that within one response the same value always gets the same placeholder wherever it appears and however it's written, and that two different values never share one. 

The same bundle, with its keys in any order, has to produce a byte-identical response every time, including after the service restarts.

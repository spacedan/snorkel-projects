The intake service at `/app/sluice/intake_server.py` turns a collected cluster support bundle into the case summary we're cleared to send to the vendor. Right now it copies the whole bundle into its response, so everything that identifies our estate leaves with it, and two runs over the same bundle don't produce the same summary.

Fix it. Keep the service at that path, keep the `--port` option working, and keep accepting a bundle as `POST /intake`. Standard library only.

Until now the release desk has cleaned these summaries by hand. `/app/fixtures/` has three collected bundles, and `/app/fixtures/cleared/` has the summary the desk cleared for each of them. Those are the reference for what the service returns: the same shape, the same kinds of thing replaced, and everything else left exactly as it was. The service has to do that for any bundle shaped like these, not only for these three. The address ranges, DNS suffixes and env-var hints the desk works from are the constants at the top of the service.

The desk's placeholder text isn't significant, so the format is up to you. What has to hold is that a placeholder doesn't contain the value it replaced, that within one response the same value always gets the same placeholder wherever it appears and however it's written, and that two different values never share one.

The same bundle, with its keys in any order, has to produce a byte-identical response every time, including after the service restarts.

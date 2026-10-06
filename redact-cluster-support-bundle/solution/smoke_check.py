"""Runs the fixed service over the sample bundles as a quick sanity check."""
import importlib.util, json, pathlib
spec = importlib.util.spec_from_file_location("intake", "/app/sluice/intake_server.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
for path in sorted(pathlib.Path("/app/fixtures").glob("*.json")):
    bundle = json.loads(path.read_text())
    case = mod.build_case(bundle)
    assert set(case) == {"items", "events", "log_excerpts"}
    text = json.dumps(case)
    for node in bundle["evidence"]["nodes"]:
        assert node["internal_ip"] not in text and node["name"] not in text
    print("ok %s items=%d events=%d lines=%d"
          % (path.name, len(case["items"]), len(case["events"]), len(case["log_excerpts"])))

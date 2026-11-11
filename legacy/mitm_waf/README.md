# Legacy: mitmproxy OSV inspection (not deployed)

The earlier lab demonstration inspected the analyst's OSV traffic by terminating
TLS in mitmproxy with a dedicated interception CA. The team profile replaced this
with the authenticated OSV broker (`service/osv_broker.py`), which applies the same
body policy (`service/osv_policy.py`) without an interception CA.

Nothing here is built into an image or applied by `run-scan.sh` / `enable_team.sh`.
It is kept only for reference and for the rollback window described in
OPERATIONS.md. `egress/proxy.py` still honours `OSV_MITM_PROXY` so this demo runs.

| File | Role |
|---|---|
| `egress_waf.py` | mitmproxy addon enforcing `service/osv_policy.py` |
| `run_proxy.py` | supervises mitmdump + `egress/proxy.py` as one service |
| `provision_ca.py`, `setup_egress_ca.py` | create the interception CA / k8s objects |
| `verify_osv_waf_local.py`, `osv_waf_probe.py` | local end-to-end check (calls public OSV/Anthropic endpoints) |

Tests (the hook tests skip unless `mitmproxy` is installed):

```bash
python -m unittest discover -s legacy/mitm_waf -t .
```

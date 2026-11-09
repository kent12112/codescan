#!/usr/bin/env bash
# One command to scan with the contained agent guaranteed up.
#   ./run-scan.sh <repo-path-or-url> [dast-target-url]
set -euo pipefail
cd "$(dirname "$0")"
REPO="${1:?usage: ./run-scan.sh <repo-path-or-url> [dast-target-url]}"
DAST_TARGET="${2:-}"

echo "==> ensuring agent, proxy, policies are applied"
kubectl apply -f k8s/proxy.yaml        >/dev/null
kubectl apply -f k8s/agent-netpol.yaml >/dev/null
kubectl apply -f k8s/agent-svc.yaml    >/dev/null
kubectl apply -f k8s/agent-pod.yaml    >/dev/null

echo "==> waiting for agent to be Ready"
kubectl wait --for=condition=ready pod/cve-agent -n scanner --timeout=120s

# The host only orchestrates Kubernetes. The scanner receives its key directly
# from a Secret; it has neither a service-account token nor a host filesystem mount.
REPORT_DIR="$(mktemp -d)"
trap 'rm -rf "$REPORT_DIR"' EXIT
SCAN_ARGS=("$REPO")

if [ -n "$DAST_TARGET" ]; then
  echo "==> running DAST (ZAP full scan) against $DAST_TARGET"
  kubectl create namespace dast >/dev/null 2>&1 || true
  kubectl delete job dast -n dast --ignore-not-found >/dev/null
  python3 - "$DAST_TARGET" <<'PYMANIFEST' | kubectl apply -f - >/dev/null
import json, sys
print(json.dumps({
    "apiVersion": "batch/v1", "kind": "Job",
    "metadata": {"name": "dast", "namespace": "dast"},
    "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 600, "template": {"spec": {
        "automountServiceAccountToken": False, "restartPolicy": "Never",
        "containers": [{"name": "zap", "image": "ghcr.io/zaproxy/zaproxy:stable",
            "imagePullPolicy": "Never", "command": ["python3", "-c",
                "import subprocess,sys; subprocess.run(['zap-full-scan.py', '-t', sys.argv[1], '-I'])"],
            "args": [sys.argv[1]]}]}}}}))
PYMANIFEST
  kubectl wait --for=condition=complete job/dast -n dast --timeout=600s || true
  kubectl logs job/dast -n dast > "$REPORT_DIR/zap-report.txt" 2>/dev/null || true
  kubectl delete job dast -n dast --ignore-not-found >/dev/null
  if grep -qE "(WARN|FAIL)-NEW" "$REPORT_DIR/zap-report.txt" 2>/dev/null; then
    SCAN_ARGS+=(--dast-report "$REPORT_DIR/zap-report.txt")
    echo "    DAST: $(grep -cE '(WARN|FAIL)-NEW' "$REPORT_DIR/zap-report.txt") alert line(s) captured"
  else
    echo "    (no DAST alerts captured; skipping DAST fold)"
  fi
fi

echo "==> scanning $REPO"
./scan-job.sh "${SCAN_ARGS[@]}"

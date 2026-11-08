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
kubectl apply -f k8s/agent-pod.yaml    >/dev/null 2>&1 || true

echo "==> waiting for agent to be Ready"
kubectl wait --for=condition=ready pod/cve-agent -n scanner --timeout=120s

echo "==> (re)starting port-forward"
pkill -f "kubectl port-forward.*cve-agent" 2>/dev/null || true
sleep 2
nohup kubectl port-forward -n scanner svc/cve-agent 9000:9000 >/tmp/pf.log 2>&1 &

echo "==> waiting for agent /healthz"
for i in $(seq 1 20); do
  curl -s --noproxy '*' -o /dev/null -w '%{http_code}' http://localhost:9000/healthz 2>/dev/null | grep -q 200 && { echo "    agent healthy"; break; }
  [ "$i" = "20" ] && { echo "ERROR: agent unreachable"; cat /tmp/pf.log; exit 1; }
  sleep 2
done

echo "==> loading API key from Secret"
export ANTHROPIC_API_KEY="$(kubectl get secret anthropic -n scanner -o jsonpath='{.data.api-key}' | base64 -d)"

if [ -n "$DAST_TARGET" ]; then
  echo "==> running DAST (ZAP full scan) against $DAST_TARGET"
  kubectl create namespace dast >/dev/null 2>&1 || true
  kubectl delete job dast -n dast --ignore-not-found >/dev/null
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata: { name: dast, namespace: dast }
spec:
  backoffLimit: 0
  template:
    metadata: { labels: { app: dast-zap } }
    spec:
      restartPolicy: Never
      containers:
      - name: zap
        image: ghcr.io/zaproxy/zaproxy:stable
        imagePullPolicy: Never
        command: ["bash","-c"]
        args: ["zap-full-scan.py -t $DAST_TARGET -I || true"]
YAML
  kubectl wait --for=condition=complete job/dast -n dast --timeout=600s || true
  kubectl logs job/dast -n dast > "$HOME/zap-report.txt" 2>/dev/null || true
  kubectl delete job dast -n dast --ignore-not-found >/dev/null
  if grep -qE "(WARN|FAIL)-NEW" "$HOME/zap-report.txt" 2>/dev/null; then
    export DAST_REPORT="$HOME/zap-report.txt"
    echo "    DAST: $(grep -cE '(WARN|FAIL)-NEW' "$HOME/zap-report.txt") alert line(s) captured"
  else
    echo "    (no DAST alerts captured; skipping DAST fold)"
  fi
fi

echo "==> scanning $REPO"
source .venv/bin/activate 2>/dev/null || true
PYTHONPATH=. python3 pipeline.py "$REPO"

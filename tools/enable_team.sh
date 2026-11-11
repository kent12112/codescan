#!/usr/bin/env bash
# Run on the lab VM after build_local_release.py has passed.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 tools/setup_internal_tls.py
kubectl apply -f k8s/llm-gateway.yaml
kubectl rollout status deployment/llm-egress-proxy -n scanner --timeout=120s
kubectl rollout status deployment/llm-gateway -n scanner --timeout=120s
kubectl apply -f k8s/proxy.yaml
kubectl rollout status deployment/osv-egress-proxy -n scanner --timeout=120s
kubectl rollout status deployment/egress-proxy -n scanner --timeout=120s
kubectl apply -f k8s/agent-netpol.yaml -f k8s/agent-svc.yaml
# Standalone Pod volumes/environment are immutable; recreate during upgrade.
kubectl delete pod cve-agent -n scanner --ignore-not-found --wait=true
kubectl apply -f k8s/agent-pod.yaml
kubectl wait --for=condition=ready pod/cve-agent -n scanner --timeout=120s
python3 tools/verify_scanner.py
kubectl exec -i -n scanner cve-agent -- python - < tests/team_cluster_probe.py

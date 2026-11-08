#!/usr/bin/env bash
# Launch an ephemeral in-cluster scan of any repo (no port-forward).
set -euo pipefail
REPO="${1:?usage: ./scan-job.sh <repo-url>}"
JOB="codescan-$(date +%s)"
kubectl apply -f - <<YAML
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB}
  namespace: scanner
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      labels: { app: codescan-scanner }
    spec:
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile: { type: RuntimeDefault }
      containers:
      - name: scanner
        image: docker.io/library/codescan-scanner:latest
        imagePullPolicy: Never
        args: ["${REPO}"]
        env:
        - name: CVE_AGENT_URL
          value: "http://cve-agent:9000/analyze"
        - name: ANTHROPIC_API_KEY
          valueFrom: { secretKeyRef: { name: anthropic, key: api-key } }
        - name: HOME
          value: /tmp
        - name: PYTHONDONTWRITEBYTECODE
          value: "1"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: { drop: ["ALL"] }
        volumeMounts: [{ name: tmp, mountPath: /tmp }]
      volumes:
      - name: tmp
        emptyDir: {}
YAML
echo "launched ${JOB} for ${REPO}"
kubectl wait --for=condition=complete job/${JOB} -n scanner --timeout=360s || true
kubectl logs job/${JOB} -n scanner

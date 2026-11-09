#!/usr/bin/env bash
# Orchestration only: source scanning and synthesis run inside the Job.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 tools/scan_job.py "$@"

# Operating the local team deployment

## Access and trust

Keep services as ClusterIP services. No NodePort, public Ingress or public gateway
is configured. Operators use individually authorized SSH / Multipass and Kubernetes
access. Do not distribute the administrator kubeconfig or shared VM credentials.
The scanner is a trusted-operator tool: generic Job creation can mount Secrets, so
an account able to create arbitrary workloads is an administrator-level trust
boundary. This repository does not provide untrusted user self-service submission,
per-user tenancy, OIDC login or a team-account provisioning service.

`k8s/readers-rbac.yaml` defines an unbound report-reader Role without Secret access,
Pod exec or workload creation. Bind it only to already authenticated, authorized
Kubernetes users. Reports and findings may reveal source secrets.

## Normal checks

```bash
export KUBECONFIG=/home/ubuntu/.kube/config
kubectl get pods,pvc -n scanner
python3 tools/verify_scanner.py
kubectl exec -i -n scanner cve-agent -- python - < tests/team_cluster_probe.py
```

Run authenticated checks after updates and certificate renewal. TCP readiness is
an availability signal for the listener; it does not prove certificate validity or
provider authentication. Alert through your existing host monitoring when these
checks fail. No external alert destination is configured automatically.

The gateway logs request IDs, workload role and elapsed time only. It does not log
prompts, response bodies or authentication headers. The analyst's local audit file
contains tool authorization metadata; tool arguments are not logged. Do not enable
SDK debug or unrestricted request logging on source-bearing services.

## Certificates and provider keys

Renew leaves monthly using `tools/setup_internal_tls.py --rotate`, then run live
checks after Secret volumes update. Preserve `codescan-internal-ca` securely: losing
its signing key requires deliberately replacing workload trust and identities.
Do not delete it as a routine troubleshooting step. Inspecting an object's name,
expiry or public certificate does not require printing Secret contents.

The provider key is mounted only by `llm-gateway`. Rotate it through the trusted
Secret-management workflow and verify the gateway after volume projection. Retain
an overlap period when the provider supports it. Never dump keys into shell history,
logs, Git or chat. Set provider spending controls independently of gateway request
quotas. The gateway reads the mounted key per request; no key is baked into images.

Legacy `egress-waf-ca` / `egress-waf-trust` objects from the MITM demonstration are
not mounted by the team profile. Retain them only for your rollback window, then
retire them through the operator's normal Secret lifecycle process.

## Reports and retention

Successful JSON reports and bounded failed-Job logs are saved on the operator host
under `reports/`, not in a shared Pod volume. Files are created owner-only. Existing
directory permissions remain an operator responsibility. Back up authorized reports
to approved storage; no external upload or notification is configured.

Preview 30-day retention cleanup before applying it:

```bash
python3 tools/prune_reports.py --days 30
python3 tools/prune_reports.py --days 30 --apply
```

Only recognized generated filenames are eligible; symlinks and other files are
excluded. The scanner's source ConfigMap and Job are deleted after completion or
normal cancellation. SIGKILL/power loss can bypass host cleanup; Job TTL and owner
references provide additional cleanup. Review orphaned source ConfigMaps after an
interrupted submission.

## Backup and recovery

Quota counters live on the `gateway-state` PVC and survive Pod replacement. This
is single-node storage: it does not survive destruction of the VM/disk without a
backup. Back up the VM and k3s data through an approved encrypted backup process,
including Secret data and the quota volume. Protect that backup as credential-
bearing data. Preserve provider credentials independently in the organization's
secret manager. Test restore into an isolated environment before relying on it.

Before a release, retain the previous source and imported image references. A failed
build/audit does not import a candidate into k3s. A deployment update is a deliberate
step after a successful build and tests. For rollback, restore the previous manifests
and images together; do not downgrade only one side of an authentication boundary.
Root CA replacement also needs a coordinated client/server trust migration.

Multipass suspend failures were observed in this lab. A healthy restart requires
waiting for guest SSH/Kubernetes readiness. If a VM is stuck in `Unknown`, inspect
current logs and processes before acting. Do not reuse old process IDs, delete disk
images or repeatedly change authentication passphrases. Forced power-off loses
unsaved state and is an operator recovery decision. This local installation has
no high-availability or disaster-recovery guarantee.

## Dependency updates and releases

`dependencies/*.lock` pins runtime packages and every accepted artifact hash. The
base image is pinned by digest. To test a dependency refresh in a candidate checkout,
update the intended direct versions, then run:

```bash
python3 tools/build_local_release.py --refresh-locks
```

The refresh resolves candidate graphs, records official PyPI artifact hashes,
rebuilds using hash enforcement, and audits before import. Review the lock changes
and new base image digest before deploying. Do not bypass failures by ignoring
vulnerability IDs or removing hashes. The previous mitmproxy/Tornado dependency
issue was removed from the active runtime by using the narrow OSV broker.

The auditor checks Python package advisories. Also review OS/base-image advisories,
container runtime, k3s, Tetragon and the Mac/VM host. This repository does not provide
a formal penetration-test, compliance certification or automatic operating-system
patching. Detection accuracy, language coverage and DAST require application-specific
validation.

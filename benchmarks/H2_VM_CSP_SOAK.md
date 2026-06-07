# H.2 VM/CSP Continuity Soak

`h2_vm_csp_soak` deploys and validates this controlled VirtualBox topology:

- VM1: CivitasOS Backend
- VM2: Cognitive Service Provider
- VM3: Alpha/Beta/Gamma Runtime phase probes

The runner invokes no LLM. It validates identity continuity, remote CSP
dual-write, local-memory-loss recovery, CSP process restart recovery, backend
delayed outcomes, and relation expectation updates.

## Safety Boundary

- Use only on a controlled host-only network.
- Backend demo-login and dev faucet are enabled by the runner.
- Identity files are preserved and must remain mode `0600`.
- Local-memory loss moves files into a quarantine directory instead of deleting
  them.
- CSP and Backend data directories are persistent across process restarts.
- The evidence is controlled deployment evidence, not production evidence.

## Default Topology

The default topology matches `~/.ssh/config` aliases `vm1`, `vm2`, and `vm3`.
Use `--topology benchmarks/h2_vm_csp_topology.example.json` to override it.

## First Smoke

```bash
cd /home/cc/Desktop/code/AIPro/ais/civitasos-agent

RUN_ROOT="runs/H2_vm_csp_$(date -u +%Y%m%dT%H%M%SZ)"

./.venv/bin/python -m benchmarks.h2_vm_csp_soak preflight \
  --run-root "$RUN_ROOT" \
  --overwrite

./.venv/bin/python -m benchmarks.h2_vm_csp_soak deploy \
  --run-root "$RUN_ROOT"

./.venv/bin/python -m benchmarks.h2_vm_csp_soak start \
  --run-root "$RUN_ROOT"

./.venv/bin/python -m benchmarks.h2_vm_csp_soak smoke \
  --run-root "$RUN_ROOT"
```

The smoke sequence performs:

1. Four real DID registrations: requester plus three workers.
2. Three task claims and Runtime/CSP dual-write shutdowns.
3. Backend settlement, dispute, and failure after worker shutdown.
4. Local SQLite memory quarantine followed by remote CSP recovery.
5. CSP process restart with its persistent data directory unchanged.
6. A second local-memory-loss recovery after CSP restart.

## Qualification And Soak

Run a short qualification before committing the VMs to a long soak:

```bash
./.venv/bin/python -m benchmarks.h2_vm_csp_soak soak \
  --run-root "$RUN_ROOT" \
  --cycles 6 \
  --interval-seconds 10 \
  --restart-csp-cycle 3 \
  --restart-backend-cycle 5
```

144-cycle qualification at one probe per ten minutes:

```bash
./.venv/bin/python -m benchmarks.h2_vm_csp_soak soak \
  --run-root "$RUN_ROOT" \
  --cycles 144 \
  --interval-seconds 600 \
  --restart-csp-cycle 36 \
  --restart-backend-cycle 72
```

This is a cycle-count qualification, not a strict 24-hour gate. With one
interval between adjacent cycles, 144 cycles can finish in less than 24 hours.
Use at least 145 cycles plus the evidence checker duration threshold for a
strict 24-hour claim:

```bash
./.venv/bin/python -m benchmarks.h2_vm_csp_soak soak \
  --run-root "$RUN_ROOT" \
  --cycles 145 \
  --interval-seconds 600 \
  --restart-csp-cycle 36 \
  --restart-backend-cycle 72

./.venv/bin/python -m benchmarks.h2_vm_csp_qualification_check \
  --run-root "$RUN_ROOT" \
  --min-cycles 145 \
  --min-duration-seconds 86400 \
  --output "$RUN_ROOT/h2_vm_csp_qualification_check.json"
```

For an existing cycle-count qualification that does not claim a full day:

```bash
./.venv/bin/python -m benchmarks.h2_vm_csp_qualification_check \
  --run-root "$RUN_ROOT" \
  --min-cycles 144 \
  --min-duration-seconds 0 \
  --output "$RUN_ROOT/h2_vm_csp_qualification_check.json"
```

Seven-day soak:

```bash
./.venv/bin/python -m benchmarks.h2_vm_csp_soak soak \
  --run-root "$RUN_ROOT" \
  --cycles 1008 \
  --interval-seconds 600 \
  --restart-csp-cycle 216 \
  --restart-csp-cycle 720 \
  --restart-backend-cycle 432
```

Every cycle starts fresh Runtime processes. By default it also quarantines
local SQLite memory, forcing CSP recovery. Use `--keep-local-memory` only for a
separate local-cache continuity comparison.

If a long run is interrupted, read `h2_vm_csp_soak_checkpoint.json` and resume
with the completed cycle as the offset:

```bash
./.venv/bin/python -m benchmarks.h2_vm_csp_soak soak \
  --run-root "$RUN_ROOT" \
  --cycle-offset 240 \
  --cycles 768 \
  --interval-seconds 600
```

## Operations

```bash
./.venv/bin/python -m benchmarks.h2_vm_csp_soak status \
  --run-root "$RUN_ROOT"

./.venv/bin/python -m benchmarks.h2_vm_csp_soak stop \
  --run-root "$RUN_ROOT"

./.venv/bin/python -m benchmarks.h2_vm_csp_soak cleanup \
  --run-root "$RUN_ROOT"
```

Important artifacts:

- `preflight.json`
- `deployment.json`
- `services.json`
- `h2_vm_csp_smoke.json`
- `h2_vm_csp_soak.json`
- `h2_vm_csp_qualification_check.json`
- `orchestrator_timeline.jsonl`
- `remote_agent/`
- `core_backend.log`
- `csp_csp.log`

VM reboot, network partition, and identity migration remain explicit operator
faults. They should be scheduled only after the process-level smoke passes.

## Nightly Boundary

Nightly may opt into the VM path, but it runs only the lightweight lifecycle:
preflight, optional deploy, start, smoke, stop, and cleanup. It never starts a
long soak.

```bash
RUN_H2_VM_CSP_SMOKE=1 \
H2_VM_CSP_SMOKE_ROOT="runs/H2_vm_csp_nightly_smoke" \
H2_VM_CSP_DEPLOY=1 \
H2_VM_CSP_CLEANUP_REMOTE=1 \
./benchmarks/run_nightly_regression.sh
```

Long-running qualification remains an explicit operator job. Nightly can
validate an already completed run without restarting services:

```bash
RUN_H2_VM_CSP_QUALIFICATION_CHECK=1 \
H2_VM_CSP_QUALIFICATION_ROOT="runs/H2_vm_csp_runner_smoke_20260606" \
H2_VM_CSP_QUALIFICATION_MIN_CYCLES=144 \
H2_VM_CSP_QUALIFICATION_MIN_DURATION_SECONDS=0 \
./benchmarks/run_nightly_regression.sh
```

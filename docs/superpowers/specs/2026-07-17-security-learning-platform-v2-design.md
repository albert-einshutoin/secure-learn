# Security Learning Platform v2 Design

## Status

- Date: 2026-07-17
- Decision: approved
- Delivery model: incremental redesign with compatibility for existing public URLs
- Required platform: macOS Docker Desktop
- Advanced platform: disposable Linux VM
- Optional platform: bounded AWS, Google Cloud, or Azure training account

## Problem

Secure Learn has a strong Docker-based SOC foundation, but its breadth is ahead of its executable evidence. The repository currently mixes runnable labs, host-assisted exercises, operational workflows, static validation, and design-only guides. Some generated checks treat the presence of terminology as curriculum coverage, and several OWASP and MITRE mappings are stale or incorrect.

The product must distinguish what a learner can read, run, prove, and perform outside Docker. It must also turn Docker-capable topics into safe attack, detection, remediation, regression, and assessment loops instead of adding more documentation-only scenarios.

## Product Goal

Build an open-source security learning platform that:

1. Works safely on macOS Docker Desktop for all mandatory foundation content.
2. Uses a disposable Linux VM for kernel, Auditd, eBPF, runtime isolation, and other host-dependent labs.
3. Offers optional real-cloud extensions without making paid infrastructure a prerequisite.
4. Teaches a topic through a guided lab, a TDD remediation exercise, evidence production, and a hidden-answer assessment.
5. Provides a shared foundation followed by role-oriented AppSec, SOC, Container/Kubernetes, Cloud/IaC/Supply Chain, and DFIR tracks.
6. Grants `verified` status only when an automated behavioral check succeeds.

Completion of the curriculum is not a professional certification and does not imply production authorization or competence on systems outside the learner's approved lab.

## Design Principles

- Evidence over terminology: documentation is not runtime proof.
- Safe by default: the launcher rejects targets and environments outside an explicit lab boundary.
- Red, blue, and fix: each executable security topic includes attack, detection, remediation, and regression.
- Progressive disclosure: beginners get guided steps; experienced learners can skip to evidence gates and assessments.
- Reproducible reset: every local lab can return to a known clean state.
- Portable core, honest exceptions: macOS is the mandatory baseline; Linux-only behavior is never simulated as verified macOS behavior.
- Small, composable labs: start only the services required for the current outcome.
- Standards are versioned data: OWASP, MITRE ATT&CK, CWE, and NIST mappings are validated rather than copied into prose.

## Learning Architecture

```text
Shared Foundation
  -> Linux, networking, HTTP, identity, Docker, secure coding, logging, ethics
Role Tracks
  -> AppSec | SOC | Container/Kubernetes | Cloud/IaC/Supply Chain | DFIR
Integrated Exercises
  -> Guided lab | Purple Team incident | Hidden-answer assessment
Work Evidence
  -> Test result | Timeline | Incident report | Remediation PR | Postmortem
```

The shared foundation supplies concepts and tool operation once. Role tracks reference those capabilities rather than duplicating introductory material. Integrated exercises combine multiple tracks only after their prerequisites are verified.

## Repository Architecture

### `curriculum/`

Machine-readable product truth:

- `schema/`: JSON Schema for labs, tracks, standards, and evidence.
- `labs/`: one manifest per lab.
- `tracks/`: ordered prerequisites and completion rules.
- `standards/`: pinned supported versions and allowed identifiers.

Generated documentation must not be the source of truth. A schema validation failure blocks CI.

### `labs/`

Executable assets grouped by learning domain:

- `appsec/`
- `detection/`
- `container/`
- `kubernetes/`
- `cloud-iac/`
- `supply-chain/`
- `dfir/`

Each lab owns its Compose overlays, fixtures, attack driver, detection assertions, remediation tests, evidence rules, assessment metadata, and reset contract.

### `platforms/`

Platform adapters implement environment checks without changing the learning contract:

- `docker-desktop`: mandatory macOS-compatible labs.
- `linux-vm`: Auditd, eBPF, Falco, namespace, kernel, and isolation labs.
- `cloud`: optional provider-specific extensions with cost and cleanup guards.

### `scripts/learn`

One public command surface:

```text
scripts/learn list
scripts/learn doctor <lab>
scripts/learn start <lab>
scripts/learn attack <lab>
scripts/learn detect <lab>
scripts/learn test <lab>
scripts/learn evidence <lab>
scripts/learn assess <lab>
scripts/learn reset <lab>
```

Existing S1-S15 commands remain available through compatibility wrappers during migration.

### `evidence/`

Generated learner evidence is ignored by Git by default. Templates and schemas remain tracked. A result contains:

- lab and standards versions;
- platform and tool versions;
- start and end timestamps;
- approved target boundary;
- expected and actual behavioral assertions;
- normalized telemetry references;
- hashes for exported evidence;
- remediation and regression outcomes;
- cleanup result.

## Lab Manifest

Every lab manifest includes:

```yaml
id: appsec-bola
version: 1
title: Broken Object Level Authorization
track: appsec
platforms:
  required: [docker-desktop]
  optional: []
maturity: verified
standards:
  owasp_api: API1:2023
  cwe: CWE-639
  nist_csf: [PR.AA, DE.CM, RS.AN]
prerequisites: [foundation-http, foundation-authz]
safety:
  target_services: [target-api]
  allowed_cidrs: [172.30.0.0/24]
  external_network: false
workflow:
  attack: attack.sh
  detect: detect.sh
  remediate: tests/remediation.test.js
  regress: tests/regression.test.js
evidence:
  required: [environment, safety, startup, attack, telemetry, pipeline, control, regression, evidence, cleanup]
assessment:
  mode: hidden-answer
  verifier: assess.sh
```

The exact schema may add descriptive fields, but it must preserve these security and verification invariants.

## Maturity Model

- `documented`: concepts and safety boundaries are reviewed.
- `runnable`: an isolated lab starts and an exercise command completes.
- `verified`: attack, expected telemetry or control behavior, remediation, regression, and cleanup are automatically asserted.
- `external`: faithful execution requires Linux VM, real cloud, hardware, or an organizational process.

Maturity is monotonic only when its required evidence exists. A missing or skipped required job cannot produce `verified` status.

The evidence SHA-256 is tamper-evidence over canonical receipt content. It is
not a signature, proof of issuer identity, or cryptographic attestation of the
runtime. In the keyless local model, only the repository runner can create the
process-private observation capability used by the verified-evidence API; a
caller-provided boolean or secret environment variable is not an observation.

## Track Scope

### AppSec and API Security

- OWASP Top 10:2025.
- OWASP API Security Top 10:2023.
- SQL injection, XSS, CSRF, path traversal, command injection, and unsafe upload.
- BOLA, object property authorization, function-level authorization, resource abuse, sensitive business flow abuse, SSRF, inventory, and unsafe API consumption.
- JWT, OAuth/OIDC, sessions, CORS, security headers, cryptography, integrity, logging, and exceptional conditions.

Executable topics use a vulnerable mode and a remediated mode backed by red and green tests. Deliberately vulnerable code is isolated from the production-mode sample app.

### SOC and Detection Engineering

- Suricata, Sigma, YARA, Auditd, normalized events, SIEM queries, and case timelines.
- MITRE ATT&CK v19 tactics and versioned technique mappings.
- Safe coverage for reconnaissance, initial access, execution, persistence, privilege escalation, credential access, discovery, lateral movement, collection, command and control, exfiltration, stealth, defense impairment, and impact.
- False-positive tuning, thresholds, allowlists, enrichment, and detection-gap reporting.

An exercise named lateral movement must cross a genuine trust or host boundary. A chained attack against one target cannot use that label.

### Container and Kubernetes Security

- Docker daemon socket, privileged containers, host mounts, capabilities, seccomp, rootless/user namespaces, secrets, resource exhaustion, image scanning, SBOMs, signatures, and provenance.
- Vulnerable and hardened Compose variants with expected-failure assertions.
- kind or k3d labs for RBAC, ServiceAccounts, Pod Security Admission, NetworkPolicy, Secrets, admission policy, audit logs, and image policy.
- Linux VM extensions for eBPF, Falco, Auditd, and host/runtime isolation.

Labs that require elevated access are unavailable on the portable path unless the adapter proves the required disposable boundary.

### Cloud, IaC, and Supply Chain

- Local emulation for basic IAM, metadata, storage policy, and request-signing concepts.
- Terraform plan, state, drift, OPA/Conftest, environment separation, and policy exceptions.
- Dependency compromise simulations, CI token boundaries, malicious artifact fixtures, SBOM differences, signing, attestations, and release provenance.
- Optional AWS, Google Cloud, and Azure exercises with budget, region, TTL, owner, and cleanup verification.

Emulation results never claim parity with provider organization policies, KMS, or production audit behavior.

### DFIR and Incident Response

- PCAP, application and security logs, file metadata, process timelines, hashing, and chain of custody.
- Safe non-executable malware fixtures and YARA analysis.
- Test-volume-only encryption simulation, backup restoration, RPO/RTO measurement, postmortem, and remediation PR evidence.
- Linux VM extensions for faithful process and kernel telemetry acquisition.

## Exercise Sequence

Each executable topic follows the same sequence:

1. `doctor` verifies tools, resources, platform, and safety boundary.
2. `start` creates only the required isolated services.
3. A guided attack demonstrates the vulnerability or failure mode.
4. Detection assertions prove which telemetry was and was not produced.
5. The learner implements or applies a remediation using supplied failing tests.
6. Regression proves the exploit fails and legitimate behavior remains available.
7. Evidence is generated in JSON and Markdown.
8. A separate assessment changes identifiers, fixtures, or symptoms and hides the answer.
9. `reset` removes the lab's containers, networks, temporary images, and disposable volumes.

## Safety Controls

- Only manifest-declared service names and CIDRs are valid attack targets.
- Public IPs, host networking, and undeclared Docker sockets are rejected.
- Lab networks use unique, non-overlapping private ranges allocated by the launcher.
- Dangerous host-dependent labs require the Linux VM adapter and a disposable-snapshot receipt.
- Malware, credentials, encryption targets, cloud resources, and secrets are synthetic and scoped to the exercise.
- Cloud labs require an explicit account allowlist, maximum cost metadata, resource TTL, and cleanup receipt.
- Commands are validated before execution; warnings alone are insufficient for prohibited targets.
- Assessment flags are stored outside normal logs and are compared without exposing expected values.
- Cleanup failure reports the exact remaining resources and exits non-zero.

## Error Model

Errors use stable categories so learners can distinguish infrastructure failure from security outcomes:

- `environment`: required engine, VM, kernel, memory, or tool is unavailable.
- `safety`: target or execution boundary is prohibited.
- `startup`: a required service did not become healthy.
- `attack`: expected vulnerable behavior was not reproduced.
- `telemetry`: the source event was absent.
- `pipeline`: telemetry existed but was not normalized or indexed.
- `control`: remediation did not block the attack.
- `regression`: legitimate behavior was broken.
- `evidence`: required proof was incomplete or internally inconsistent.
- `cleanup`: lab-owned resources remain.

Attack success, detection success, and defense success are separate results. Partial success cannot be collapsed into a passing status.

## Testing Strategy

Tests are written before behavioral implementation for every new lab or defect correction.

### Fast CI

- Manifest and standards schema validation.
- Generator determinism and stale-output checks.
- Unit tests for target validation, platform selection, result classification, and evidence hashing.
- Compose configuration, shell syntax, TypeScript type checks, security tests, and static Kubernetes policy checks.

### Docker E2E

- Fresh-volume start.
- Vulnerable behavior reproduction.
- Telemetry source assertion.
- Pipeline and SIEM assertion where applicable.
- Hardened behavior and legitimate-flow regression.
- Assessment verifier behavior.
- Complete cleanup assertion.

Labs run as independent CI matrix jobs to contain failures and resource use.

### Linux VM CI

Kernel-dependent jobs run separately on an approved Linux runner. A skipped job is reported as unsupported or unverified, never passed.

### Optional Cloud Validation

Static and emulator checks run in normal CI. Real-provider jobs are scheduled or manually dispatched with budget and cleanup controls. They are not required for the portable-core release gate.

## Documentation Generation

README summaries, track pages, scenario pages, platform matrices, standards coverage, and maturity tables are generated from manifests. Generated pages are checked for deterministic output and staleness.

Human-authored content remains appropriate for explanations, threat models, remediation rationale, and operational judgment. It cannot alter maturity or standards mappings outside validated data.

## Compatibility and Migration

1. Preserve public S1-S15 URLs and commands.
2. Introduce the manifest schema, standards catalog, launcher, and evidence model.
3. Import existing S1-S15 with honest maturity values.
4. Correct OWASP and MITRE mappings before adding new coverage.
5. Extend automated telemetry checks from five scenarios to every Docker-backed legacy scenario.
6. Add executable AppSec and container-security labs first because they are high-value and portable.
7. Add kind/k3d, identity/cryptography, detection/DFIR, recovery, and supply-chain labs.
8. Add Linux VM adapters and exercises.
9. Add optional real-cloud extensions.
10. Promote an existing design exercise only after its full `verified` contract passes.

S16-S33 remain available as design exercises during migration. They are consolidated or promoted only when doing so preserves public navigation and improves evidence depth.

## Delivery Slices

### Slice 1: Truth and Safety Foundation

- Standards corrections.
- Manifest schema and existing-scenario inventory.
- Maturity enforcement.
- Unified CLI foundation.
- Target boundary and evidence tests.
- Generated coverage report replacing keyword-only success claims.

### Slice 2: Portable AppSec Core

- Authorization, SSRF, resource abuse, browser-facing, identity, cryptography, and exceptional-condition labs.
- Vulnerable/remediated modes and TDD exercises.
- Hidden-answer assessments.

### Slice 3: Portable Container and Kubernetes Core

- Docker misconfiguration and hardening labs.
- Image and supply-chain verification.
- kind/k3d policy and identity labs.

### Slice 4: SOC, DFIR, and Recovery

- Full legacy scenario E2E coverage.
- Versioned ATT&CK mapping.
- Sigma/YARA/PCAP/timeline exercises.
- Backup and recovery drill.

### Slice 5: Linux and Cloud Extensions

- Disposable Linux VM bootstrap and receipts.
- Auditd, eBPF, Falco, and kernel isolation.
- Provider-neutral cloud contract plus optional provider modules.

Each slice is independently releasable, documented, and covered by its own quality gate.

## Success Criteria

- Every published lab has a valid manifest and explicit platform boundary.
- Every `verified` lab has automated attack, outcome, remediation, regression, evidence, and cleanup checks.
- All Docker-backed legacy scenarios have behavioral E2E coverage.
- OWASP API 2023 and MITRE ATT&CK v19 mappings pass catalog validation.
- The product UI and README never count documentation as runtime verification.
- Portable mandatory tracks complete without a paid account or unsafe host mutation.
- Linux-only and cloud-only outcomes are clearly separated from portable results.
- A learner can produce an auditable report and remediation artifact for each completed track.
- Existing public S1-S15 entry points remain usable throughout migration.

## Non-Goals

- Simulating real cloud organization behavior entirely with local emulators.
- Running kernel exploits or authentic malware on the learner's daily-use host.
- Claiming that curriculum completion certifies professional competence.
- Reproducing physical, wireless, OT, hardware, or enterprise Windows environments inside Docker.
- Maximizing scenario count at the expense of executable depth.

## Architectural Decisions

- Incremental redesign is chosen over a rewrite to preserve OSS compatibility and reviewability.
- A portable core plus Linux extension is chosen over lowest-common-denominator simulation.
- Role tracks share prerequisites instead of duplicating foundational content.
- Guided labs precede hidden-answer assessments so the product teaches before it evaluates.
- Local OSS is mandatory; paid cloud is optional.
- Manifest-driven maturity replaces prose and keyword-based completion claims.

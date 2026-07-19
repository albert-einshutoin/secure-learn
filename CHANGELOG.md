# Changelog

All notable changes to Secure Learn are documented here. This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Added versioned OWASP API Security 2023 and MITRE ATT&CK Enterprise v19 catalogs plus one validated manifest for each legacy S1-S15 scenario. The inventory truth is 12 `runnable`, 2 `external`, 1 `documented`, and **0 `verified`**; runnable content is not presented as verified.
- Added the dependency-free `scripts/learn` discovery, validation, and platform-doctor interface, including operator-attested disposable Linux VM readiness receipts for host-assisted S5 and S6.
- Added deterministic outcome classification, policy-bound evidence hashing, and generated curriculum coverage so maturity claims are reproducible from tracked manifests.

### Changed

- Raised the Docker runtime contract to Engine 28.1.0/API 1.49 for Compose `interface_name`, and pinned the fresh-stack CI daemon to Docker CE 29.6.2, whose official release includes multiple security fixes, with a fail-closed local-socket/version gate.
- Corrected public OWASP API and MITRE ATT&CK taxonomy, scenario semantics, and generated guides while retaining the existing public S1-S15 URLs.
- Enforced manifest, coverage, taxonomy, generator-idempotency, and safety contracts in the canonical local quality gate and CI.
- Stage all release evidence on a draft before publication so immutable releases never expose a partial asset set.
- Run JavaScript/TypeScript CodeQL as a required CI gate and remove the incomplete regular-expression sanitization it identified.

### Security

- Bound learner attack targets to manifest-declared services and private CIDRs, kept learner execution on fixed argv boundaries, and isolated generated evidence with restrictive permissions and ignored runtime paths.
- Included the digest-pinned IPS helper in build verification, Trivy reports, SPDX SBOMs, and release checksums, and documented the Docker socket as a trusted release-tooling-only exception.
- Kept attack and database networks internal on Linux and Docker Desktop while restoring loopback-only host access through a digest-pinned, non-root, read-only, capability-free TCP publisher with IP forwarding disabled and bounded CPU, memory, PID, file-descriptor, and child-connection limits; fresh-stack E2E now proves egress, route-bypass, resource-exhaustion, data-plane, and IDS boundaries.
- Added the host publisher as a fourth release image with Trivy, SPDX SBOM, checksum, and GitHub artifact attestation evidence.
- This foundation does not claim executable AppSec, Kubernetes, DFIR, Linux, or cloud expansion labs; those remain follow-up slices until their own verification workflows satisfy the `verified` contract.

## [1.0.0] - 2026-07-17

### Added

- Reproducible Docker SOC lab with Suricata, Fail2ban, Elasticsearch, Kibana, Filebeat, PostgreSQL, and a remediated NestJS API.
- Thirty-three scenario guides split into Docker labs, Linux-host-assisted exercises, operator workflows, and guided design reviews.
- Fresh-volume end-to-end verification for application, IDS, SIEM bootstrap, event ingestion, data views, and dashboards.
- Release SBOMs, HIGH/CRITICAL vulnerability gates, checksums, and GitHub artifact attestations.

### Security

- Upgraded Suricata to 8.0.6 and the Elastic Stack to 8.19.17, pinned by multi-architecture digest.
- Removed unused npm tooling from the application runtime image to reduce its executable and vulnerable package surface.
- Replaced unsafe account-control file mutation examples with disposable Linux VM and `/tmp`-only exercises.

[Unreleased]: https://github.com/albert-einshutoin/secure-learn/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/albert-einshutoin/secure-learn/releases/tag/v1.0.0

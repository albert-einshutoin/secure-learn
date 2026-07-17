# Changelog

All notable changes to Secure Learn are documented here. This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Stage all release evidence on a draft before publication so immutable releases never expose a partial asset set.
- Run JavaScript/TypeScript CodeQL as a required CI gate and remove the incomplete regular-expression sanitization it identified.

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

# Security Policy

## Supported Use

Secure Learn / SOC-Lab is a security training environment that generates
attack traffic and security telemetry. The default API rejects the bundled SQL
injection and path-traversal payloads and enforces authenticated role access.
Predictable demonstration credentials and authentication-disabled observability
services remain intentionally local-only.

Do not expose the lab to the public internet.

## Reporting a Vulnerability

If you find a vulnerability in the lab infrastructure that could affect users
outside the intended training scenarios, please open a private security advisory
on GitHub or contact the maintainers through the repository security page.

Please include:

- A clear description of the issue.
- Steps to reproduce.
- The affected component.
- Whether the issue can escape the Docker lab boundary.

## Intended Training Behavior

Attack scripts, weak local-only demonstration credentials, suspicious payloads,
and detection exercises are expected training material. SQL injection and path
traversal requests are logged but rejected by the default API. A bypass that
escapes those controls, trusts forged client identity, exposes services beyond
localhost, or escapes the Docker lab boundary is a security vulnerability.

## Safety Rules

- Keep all attack traffic inside the lab networks.
- Do not run attack scripts against third-party hosts.
- Do not commit real credentials, Slack webhooks, private keys, packet captures
  containing sensitive traffic, or local `.env` files.

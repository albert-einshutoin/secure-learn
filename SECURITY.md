# Security Policy

## Supported Use

Secure Learn / SOC-Lab is an intentionally vulnerable training environment.
Run it only on machines and networks you control.

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

## Intended Vulnerabilities

The vulnerable NestJS app, SQL injection endpoints, weak credentials, path
traversal behavior, attack scripts, and detection bypass exercises are expected
training material. Reports about those intentional behaviors should be filed as
documentation or scenario-improvement issues, not as security vulnerabilities.

## Safety Rules

- Keep all attack traffic inside the lab networks.
- Do not run attack scripts against third-party hosts.
- Do not commit real credentials, Slack webhooks, private keys, packet captures
  containing sensitive traffic, or local `.env` files.

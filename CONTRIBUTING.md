# Contributing

Thanks for helping improve Secure Learn / SOC-Lab.

## Scope

This project is an intentionally vulnerable, local-only security training lab.
Contributions should preserve that purpose:

- Keep attack traffic inside the Docker lab or explicitly documented host-only exercises.
- Do not add code that targets third-party systems.
- Prefer deterministic hands-on steps over environment-specific assumptions.
- Add or update scenario documentation when changing lab behavior.

## Development Flow

1. Open an issue or discussion for larger behavior changes.
2. Create a branch from `main`.
3. Make focused commits.
4. Run the checks below before opening a pull request.

```bash
cd app
npm ci
npm run build
cd ..
docker compose config -q
docker compose -f docker-compose.yml -f docker-compose.alerting.yml config -q
docker compose -f docker-compose.yml -f docker-compose.ips.yml config -q
docker compose -f docker-compose.exercise.yml config -q
```

## Pull Request Checklist

- [ ] The lab still starts with Docker Compose.
- [ ] Any new attack behavior is documented as local-only.
- [ ] Detection, response, and verification steps are updated.
- [ ] Generated files, logs, secrets, and local `.env` files are not committed.
- [ ] Security implications are called out in the PR description.

## Code Style

Use the existing project style. Add comments when a decision is security-
relevant, intentionally vulnerable, or non-obvious for lab stability.

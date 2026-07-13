## Why

Explain the user or maintainer problem, its impact, and why the change belongs in Secure Learn.

## Before / After

- Before:
- After:

## Implementation decisions

Describe the architecture, security boundary, and non-obvious tradeoffs. Call out why the chosen approach is appropriate for a local OSS training lab.

## Verification

- [ ] Test was added or updated before the implementation (TDD)
- [ ] `npm --prefix app run check`
- [ ] `npm --prefix app test`
- [ ] `node --test test/product-readiness.test.js`
- [ ] Relevant Compose and runtime flows were verified
- [ ] Generated guides were regenerated and checked when applicable
- [ ] `npm --prefix app audit --omit=dev --audit-level=high`

## Safety and OSS quality

- [ ] Host ports remain restricted to localhost
- [ ] No real credentials, webhooks, packet captures, logs, or local environment files are included
- [ ] Attack behavior remains limited to systems and networks controlled by the learner
- [ ] Documentation explains any changed behavior and its limitations

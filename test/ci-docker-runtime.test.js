const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const verifier = path.join(root, 'scripts', 'verify_ci_docker_runtime.sh');

function runVerifier(overrides = {}) {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-ci-docker-'));
  const fakeDocker = path.join(fixture, 'docker');
  fs.writeFileSync(fakeDocker, `#!/bin/sh
set -eu
case "$*" in
  "context show") printf '%s\\n' "\${FAKE_CONTEXT}" ;;
  "context inspect "*" --format {{.Endpoints.docker.Host}}") printf '%s\\n' "\${FAKE_ENDPOINT}" ;;
  "version --format {{.Server.Version}} {{.Server.APIVersion}}") printf '%s %s\\n' "\${FAKE_ENGINE}" "\${FAKE_API}" ;;
  "compose version --short") printf '%s\\n' "\${FAKE_COMPOSE}" ;;
  *) exit 64 ;;
esac
`, { mode: 0o755 });

  const env = {
    PATH: `${fixture}:/usr/bin:/bin`,
    EXPECTED_DOCKER_SOCKET: 'unix:///tmp/docker.sock',
    FAKE_CONTEXT: 'secure-learn-ci',
    FAKE_ENDPOINT: 'unix:///tmp/docker.sock',
    FAKE_ENGINE: '29.6.2',
    FAKE_API: '1.54',
    FAKE_COMPOSE: '2.36.0',
    ...overrides,
  };
  const result = spawnSync('/bin/bash', [verifier], {
    cwd: root,
    encoding: 'utf8',
    env,
  });
  fs.rmSync(fixture, { recursive: true, force: true });
  return result;
}

test('CI Docker verifier accepts the action Unix socket and compatible exact versions', () => {
  const result = runVerifier();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'Docker runtime contract verified.\n');
});

test('CI Docker verifier rejects unsafe or mismatched socket contracts', () => {
  for (const overrides of [
    { EXPECTED_DOCKER_SOCKET: 'unix://unix:///tmp/docker.sock', FAKE_ENDPOINT: 'unix://unix:///tmp/docker.sock' },
    { EXPECTED_DOCKER_SOCKET: '/tmp/docker.sock', FAKE_ENDPOINT: '/tmp/docker.sock' },
    { EXPECTED_DOCKER_SOCKET: 'tcp://127.0.0.1:2375', FAKE_ENDPOINT: 'tcp://127.0.0.1:2375' },
    { FAKE_ENDPOINT: 'unix:///tmp/other.sock' },
    { DOCKER_HOST: 'unix:///tmp/docker.sock' },
    { DOCKER_CONTEXT: 'secure-learn-ci' },
  ]) {
    const result = runVerifier(overrides);
    assert.notEqual(result.status, 0, JSON.stringify(overrides));
  }
});

test('CI Docker verifier rejects malformed, old, prerelease, or unexpected versions', () => {
  for (const overrides of [
    { FAKE_ENGINE: '29.6.1' },
    { FAKE_ENGINE: '29.6.2-rc.1' },
    { FAKE_API: '1.48' },
    { FAKE_API: 'v1.54' },
    { FAKE_COMPOSE: '2.35.99' },
    { FAKE_COMPOSE: '2.36.0-rc.1' },
  ]) {
    const result = runVerifier(overrides);
    assert.notEqual(result.status, 0, JSON.stringify(overrides));
  }
});

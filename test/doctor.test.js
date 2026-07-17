const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');

const {
  checkDockerDesktop,
  doctorManifest,
  INFO_FORMAT,
} = require('../scripts/lib/doctor');

const root = path.resolve(__dirname, '..');

function successSpawn(calls) {
  return (binary, argv, options) => {
    calls.push({ binary, argv, options });
    if (argv[0] === 'context') {
      return { status: 0, stdout: `${JSON.stringify('unix:///Users/student/.docker/run/docker.sock')}\n`, stderr: '' };
    }
    return {
      status: 0,
      stdout: `${JSON.stringify({ operatingSystem: 'Docker Desktop', osType: 'linux', name: 'docker-desktop' })}\n`,
      stderr: '',
    };
  };
}

test('Docker Desktop doctor pins context, identity, argv, and spawn boundaries', () => {
  const calls = [];
  const result = checkDockerDesktop({
    platform: 'darwin',
    home: '/Users/student',
    repositoryRoot: root,
    findDocker: () => '/trusted/docker',
    spawn: successSpawn(calls),
  });

  assert.deepEqual(result, { ok: true, message: 'Platform ready: docker-desktop' });
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].argv, [
    'context', 'inspect', 'desktop-linux', '--format', '{{json .Endpoints.docker.Host}}',
  ]);
  assert.deepEqual(calls[1].argv, ['--context', 'desktop-linux', 'info', '--format', INFO_FORMAT]);
  for (const call of calls) {
    assert.equal(call.binary, '/trusted/docker');
    assert.equal(call.options.cwd, root);
    assert.equal(call.options.shell, false);
    assert.equal(call.options.timeout, 15_000);
    assert.equal(call.options.maxBuffer, 64 * 1024);
    assert.deepEqual(call.options.env, {
      HOME: '/Users/student',
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
      DOCKER_CLI_HINTS: 'false',
    });
  }
});

test('Docker Desktop doctor rejects non-macOS, missing CLI, remote contexts, and fake engines', () => {
  const base = {
    platform: 'darwin',
    home: '/Users/student',
    repositoryRoot: root,
    findDocker: () => '/trusted/docker',
  };
  assert.equal(checkDockerDesktop({ ...base, platform: 'linux' }).ok, false);
  assert.equal(checkDockerDesktop({ ...base, findDocker: () => null }).ok, false);

  const remote = checkDockerDesktop({
    ...base,
    spawn: () => ({ status: 0, stdout: `${JSON.stringify('tcp://attacker:2375')}\n`, stderr: '' }),
  });
  assert.equal(remote.ok, false);

  let count = 0;
  const fakeEngine = checkDockerDesktop({
    ...base,
    spawn: () => {
      count += 1;
      return count === 1
        ? { status: 0, stdout: `${JSON.stringify('unix:///Users/student/.docker/run/docker.sock')}\n`, stderr: '' }
        : { status: 0, stdout: JSON.stringify({ operatingSystem: 'Ubuntu', osType: 'linux', name: 'remote' }), stderr: '' };
    },
  });
  assert.equal(fakeEngine.ok, false);
});

test('Docker Desktop doctor fails closed on spawn, timeout, malformed, and oversized output', () => {
  const secret = 'never-reflect-this';
  const base = {
    platform: 'darwin',
    home: '/Users/student',
    repositoryRoot: root,
    findDocker: () => '/trusted/docker',
  };
  for (const spawn of [
    () => ({ status: null, error: new Error(secret), stdout: '', stderr: secret }),
    () => ({ status: null, signal: 'SIGTERM', error: Object.assign(new Error(secret), { code: 'ETIMEDOUT' }), stdout: '', stderr: '' }),
    () => ({ status: 0, stdout: '{not json', stderr: '' }),
    () => ({ status: 0, stdout: 'x'.repeat(64 * 1024 + 1), stderr: '' }),
  ]) {
    const result = checkDockerDesktop({ ...base, spawn });
    assert.equal(result.ok, false);
    assert.match(result.message, /Docker Desktop is not ready/);
    assert.doesNotMatch(result.message, new RegExp(secret));
  }
});

test('doctor dependency injection cannot be activated by product environment variables', () => {
  const manifest = {
    id: 's1',
    platforms: { required: ['docker-desktop'] },
    safety: { target_services: ['app'], allowed_cidrs: ['172.23.0.0/24'], external_network: false },
  };
  let checks = 0;
  assert.throws(() => doctorManifest(manifest, {
    env: { NODE_ENV: 'test', SECURE_LEARN_SKIP_DOCKER_CHECK: '1' },
    checkDocker: () => {
      checks += 1;
      return { ok: false, message: 'Docker Desktop is not ready.' };
    },
  }), /not ready/);
  assert.equal(checks, 1);
});

test('Linux doctor binds the receipt to the lab and reports its operator-attested assurance', () => {
  const manifest = {
    id: 's5',
    platforms: { required: ['linux-vm'] },
    safety: { target_services: [], allowed_cidrs: [], external_network: false },
  };
  let receiptCall;
  const output = doctorManifest(manifest, {
    platform: 'linux',
    repositoryRoot: root,
    env: { SECURE_LEARN_VM_RECEIPT: 'evidence/vm-receipts/s5.json' },
    validateReceipt: (...args) => { receiptCall = args; },
  });
  assert.equal(receiptCall[0], 'evidence/vm-receipts/s5.json');
  assert.equal(receiptCall[1].expectedLabId, 's5');
  assert.equal(receiptCall[1].repositoryRoot, root);
  assert.match(output, /^Platform ready: linux-vm \(operator-attested local VM receipt\)\n/);
});

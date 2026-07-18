const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');

const {
  checkDockerPlatform,
  doctorManifest,
  INFO_FORMAT,
  parseComposeVersion,
} = require('../scripts/lib/doctor');

const root = path.resolve(__dirname, '..');
const composeConfig = JSON.stringify({
  services: {
    'target-netns': {
      networks: {
        app_net: { interface_name: 'eth0' },
        data_net: { interface_name: 'eth1' },
      },
    },
  },
});

function platformSpawn(calls, {
  contextHost,
  identity,
  context = contextHost.startsWith('unix:///run/user/') ? 'rootless'
    : contextHost === 'unix:///var/run/docker.sock' ? 'default'
      : 'desktop-linux',
  composeVersion = '2.36.0',
  config = composeConfig,
}) {
  return (binary, argv, options) => {
    calls.push({ binary, argv, options });
    if (argv[0] === 'context' && argv[1] === 'show') {
      return { status: 0, stdout: `${context}\n`, stderr: '' };
    }
    if (argv[0] === 'context') {
      return { status: 0, stdout: `${JSON.stringify(contextHost)}\n`, stderr: '' };
    }
    if (argv.includes('info')) {
      return { status: 0, stdout: `${JSON.stringify(identity)}\n`, stderr: '' };
    }
    if (argv.includes('version')) {
      return { status: 0, stdout: `${composeVersion}\n`, stderr: '' };
    }
    return { status: 0, stdout: `${config}\n`, stderr: '' };
  };
}

const cases = [
  {
    name: 'macOS Docker Desktop',
    platform: 'darwin',
    home: '/Users/student',
    uid: 501,
    context: 'desktop-linux',
    contextHost: 'unix:///Users/student/.docker/run/docker.sock',
    identity: { operatingSystem: 'Docker Desktop', osType: 'linux', name: 'docker-desktop' },
    expectedPlatform: 'docker-desktop-macos',
    expectedPath: '/usr/bin:/bin:/usr/sbin:/sbin',
  },
  {
    name: 'Windows Docker Desktop',
    platform: 'win32',
    home: 'C:\\Users\\student',
    context: 'desktop-linux',
    contextHost: 'npipe:////./pipe/dockerDesktopLinuxEngine',
    identity: { operatingSystem: 'Docker Desktop', osType: 'linux', name: 'docker-desktop' },
    expectedPlatform: 'docker-desktop-windows',
    expectedPath: 'C:\\Windows\\System32',
  },
  {
    name: 'Linux local Docker Engine',
    platform: 'linux',
    home: '/home/student',
    uid: 1000,
    context: 'rootless',
    contextHost: 'unix:///var/run/docker.sock',
    identity: { operatingSystem: 'Ubuntu 24.04', osType: 'linux', name: 'student-workstation' },
    expectedPlatform: 'docker-engine-linux',
    expectedPath: '/usr/bin:/bin:/usr/sbin:/sbin',
  },
  {
    name: 'Linux rootless Docker Engine',
    platform: 'linux',
    home: '/home/student',
    uid: 1000,
    context: 'default',
    contextHost: 'unix:///run/user/1000/docker.sock',
    identity: { operatingSystem: 'Ubuntu 24.04', osType: 'linux', name: 'student-workstation' },
    expectedPlatform: 'docker-engine-linux',
    expectedPath: '/usr/bin:/bin:/usr/sbin:/sbin',
  },
];

for (const scenario of cases) {
  test(`${scenario.name} doctor pins local identity, Compose capability, argv, and spawn boundaries`, () => {
    const calls = [];
    const result = checkDockerPlatform({
      platform: scenario.platform,
      home: scenario.home,
      uid: scenario.uid,
      repositoryRoot: root,
      findDocker: () => scenario.platform === 'win32' ? 'C:\\trusted\\docker.exe' : '/trusted/docker',
      spawn: platformSpawn(calls, scenario),
    });

    assert.deepEqual(result, { ok: true, platform: scenario.expectedPlatform, message: `Platform ready: ${scenario.expectedPlatform}` });
    assert.equal(calls.length, 5);
    assert.deepEqual(calls[0].argv, ['context', 'show']);
    assert.deepEqual(calls[1].argv, [
      'context', 'inspect', scenario.context, '--format', '{{json .Endpoints.docker.Host}}',
    ]);
    assert.deepEqual(calls[2].argv, ['--context', scenario.context, 'info', '--format', INFO_FORMAT]);
    assert.deepEqual(calls[3].argv, ['--context', scenario.context, 'compose', 'version', '--short']);
    assert.deepEqual(calls[4].argv, ['--context', scenario.context, 'compose', '-f', 'docker-compose.yml', 'config', '--format', 'json']);
    for (const call of calls) {
      assert.equal(call.options.cwd, root);
      assert.equal(call.options.shell, false);
      assert.equal(call.options.timeout, 15_000);
      assert.equal(call.options.maxBuffer, 64 * 1024);
      assert.equal(call.options.env.PATH, scenario.expectedPath);
      assert.equal(call.options.env.DOCKER_CLI_HINTS, 'false');
      assert.equal(call.options.env.HOME, scenario.home);
      assert.equal(Object.hasOwn(call.options.env, 'DOCKER_HOST'), false);
      assert.equal(Object.hasOwn(call.options.env, 'DOCKER_CONTEXT'), false);
    }
  });
}

test('Compose versions are compared as numeric semver at the 2.36.0 boundary', () => {
  assert.deepEqual(parseComposeVersion('2.36.0'), [2, 36, 0]);
  assert.deepEqual(parseComposeVersion('v5.1.4'), [5, 1, 4]);
  assert.deepEqual(parseComposeVersion('2.36.0-desktop.1'), [2, 36, 0]);
  for (const value of ['2.35.99', '2.9.100', '2.36', '2.36.x', '2.36.0 trailing', '999999999999999999.0.0']) {
    assert.equal(parseComposeVersion(value), null);
  }
});

test('Docker doctor rejects remote, ambiguous, spoofed, old, and incapable engines on every OS', () => {
  const identities = {
    darwin: { operatingSystem: 'Docker Desktop', osType: 'linux', name: 'docker-desktop' },
    win32: { operatingSystem: 'Docker Desktop', osType: 'linux', name: 'docker-desktop' },
    linux: { operatingSystem: 'Ubuntu', osType: 'linux', name: 'local' },
  };
  const homes = { darwin: '/Users/student', win32: 'C:\\Users\\student', linux: '/home/student' };
  const badHosts = ['tcp://127.0.0.1:2375', 'ssh://student@host', 'https://cloud.example', 'unix:///tmp/docker.sock', 'npipe:////./pipe/ambiguous'];
  for (const platform of ['darwin', 'win32', 'linux']) {
    const base = {
      platform,
      home: homes[platform],
      uid: 1000,
      repositoryRoot: root,
      findDocker: () => platform === 'win32' ? 'C:\\trusted\\docker.exe' : '/trusted/docker',
    };
    for (const contextHost of badHosts) {
      const result = checkDockerPlatform({
        ...base,
        spawn: platformSpawn([], {
          context: platform === 'linux' ? 'default' : 'desktop-linux',
          contextHost,
          identity: identities[platform],
        }),
      });
      assert.equal(result.ok, false, `${platform} must reject ${contextHost}`);
    }

    const expectedHost = platform === 'darwin'
      ? 'unix:///Users/student/.docker/run/docker.sock'
      : platform === 'win32'
        ? 'npipe:////./pipe/dockerDesktopLinuxEngine'
        : 'unix:///var/run/docker.sock';
    for (const override of [
      { identity: { operatingSystem: 'Docker Desktop', osType: 'windows', name: 'docker-desktop' } },
      { identity: { operatingSystem: 'Docker Desktop', osType: 'linux', name: 'remote' } },
      { composeVersion: '2.35.99' },
      { config: JSON.stringify({ services: { 'target-netns': { networks: { app_net: {}, data_net: {} } } } }) },
    ]) {
      const result = checkDockerPlatform({
        ...base,
        spawn: platformSpawn([], {
          context: platform === 'linux' ? 'default' : 'desktop-linux',
          contextHost: expectedHost,
          identity: identities[platform],
          ...override,
        }),
      });
      assert.equal(result.ok, false, `${platform} must fail closed for ${JSON.stringify(override)}`);
    }
  }
});

test('Docker doctor rejects an active remote or unknown context before engine inspection', () => {
  for (const [platform, activeContext] of [['darwin', 'production'], ['win32', 'ssh-prod'], ['linux', 'cloud']]) {
    let calls = 0;
    const result = checkDockerPlatform({
      platform,
      home: platform === 'win32' ? 'C:\\Users\\student' : platform === 'darwin' ? '/Users/student' : '/home/student',
      uid: 1000,
      repositoryRoot: root,
      findDocker: () => platform === 'win32' ? 'C:\\trusted\\docker.exe' : '/trusted/docker',
      spawn: () => {
        calls += 1;
        return { status: 0, stdout: `${activeContext}\n`, stderr: '' };
      },
    });
    assert.equal(result.ok, false);
    assert.equal(calls, 1);
  }
});

test('Docker doctor fails closed on missing CLI, spawn errors, malformed, and oversized output', () => {
  const base = {
    platform: 'darwin',
    home: '/Users/student',
    repositoryRoot: root,
    findDocker: () => '/trusted/docker',
  };
  assert.equal(checkDockerPlatform({ ...base, findDocker: () => null }).ok, false);
  for (const spawn of [
    () => ({ status: null, error: new Error('secret'), stdout: '', stderr: 'secret' }),
    () => ({ status: 0, stdout: '{not json', stderr: '' }),
    () => ({ status: 0, stdout: 'x'.repeat(64 * 1024 + 1), stderr: '' }),
  ]) {
    const result = checkDockerPlatform({ ...base, spawn });
    assert.deepEqual(result, { ok: false, message: 'Docker platform is not ready.' });
  }
});

test('doctor chooses only the current OS platform declared by a Docker lab', () => {
  const manifest = {
    id: 's1',
    platforms: {
      required: ['docker-desktop-macos', 'docker-desktop-windows', 'docker-engine-linux'],
      optional: [],
    },
    safety: { target_services: ['app'], allowed_cidrs: ['172.23.0.0/24'], external_network: false },
  };
  let checks = 0;
  const output = doctorManifest(manifest, {
    platform: 'linux',
    env: { SECURE_LEARN_SKIP_DOCKER_CHECK: '1' },
    checkDocker: () => {
      checks += 1;
      return { ok: true, platform: 'docker-engine-linux', message: 'Platform ready: docker-engine-linux' };
    },
  });
  assert.equal(checks, 1);
  assert.match(output, /^Platform ready: docker-engine-linux\n/);

  assert.throws(() => doctorManifest({
    ...manifest,
    platforms: { required: ['docker-desktop-macos'], optional: [] },
  }, {
    platform: 'linux',
    checkDocker: () => ({ ok: true, platform: 'docker-engine-linux', message: 'spoofed' }),
  }), /not declared/);
});

test('doctor dependency injection cannot be activated by product environment variables', () => {
  const manifest = {
    id: 's1',
    platforms: { required: ['docker-desktop-macos', 'docker-desktop-windows', 'docker-engine-linux'], optional: [] },
    safety: { target_services: ['app'], allowed_cidrs: ['172.23.0.0/24'], external_network: false },
  };
  assert.throws(() => doctorManifest(manifest, {
    platform: 'darwin',
    env: { NODE_ENV: 'test', SECURE_LEARN_SKIP_DOCKER_CHECK: '1' },
    checkDocker: () => ({ ok: false, message: 'Docker platform is not ready.' }),
  }), /not ready/);
});

test('Linux doctor binds the receipt to the lab and reports its operator-attested assurance', () => {
  const manifest = {
    id: 's5',
    platforms: { required: ['linux-vm'], optional: [] },
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

test('Linux VM receipt doctor must run inside the VM, not from the host', () => {
  const manifest = {
    id: 's5',
    platforms: { required: ['linux-vm'], optional: [] },
    safety: { target_services: [], allowed_cidrs: [], external_network: false },
  };
  for (const platform of ['darwin', 'win32']) {
    assert.throws(() => doctorManifest(manifest, { platform }), /checked from a Linux VM/);
  }
});

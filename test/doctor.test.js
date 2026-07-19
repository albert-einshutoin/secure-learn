const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  checkDockerPlatform,
  doctorManifest,
  INFO_FORMAT,
  parseComposeVersion,
  VERSION_FORMAT,
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
  server = { apiVersion: '1.54', os: 'linux', version: identity.serverVersion },
  runtimeStatus = 0,
  cleanupStatus = 0,
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
    if (argv.includes('version') && !argv.includes('compose')) {
      return { status: 0, stdout: `${JSON.stringify(server)}\n`, stderr: '' };
    }
    if (argv.includes('version')) {
      return { status: 0, stdout: `${composeVersion}\n`, stderr: '' };
    }
    if (argv.includes('config')) return { status: 0, stdout: `${config}\n`, stderr: '' };
    if (argv.includes('down')) return { status: cleanupStatus, stdout: '', stderr: '' };
    return { status: runtimeStatus, stdout: '', stderr: '' };
  };
}

function socketStat(uid, gid = uid, mode = 0o140700) {
  return { uid, gid, mode, isSocket: () => true };
}

const cases = [
  {
    name: 'macOS Docker Desktop',
    platform: 'darwin',
    home: '/Users/student',
    uid: 501,
    context: 'desktop-linux',
    contextHost: 'unix:///Users/student/.docker/run/docker.sock',
    identity: { operatingSystem: 'Docker Desktop', osType: 'linux', name: 'docker-desktop', serverVersion: '29.5.3' },
    expectedPlatform: 'docker-desktop-macos',
    expectedPath: '/usr/bin:/bin:/usr/sbin:/sbin',
  },
  {
    name: 'Windows Docker Desktop',
    platform: 'win32',
    home: 'C:\\Users\\student',
    context: 'desktop-linux',
    contextHost: 'npipe:////./pipe/dockerDesktopLinuxEngine',
    identity: { operatingSystem: 'Docker Desktop', osType: 'linux', name: 'docker-desktop', serverVersion: '29.5.3' },
    expectedPlatform: 'docker-desktop-windows',
    expectedPath: 'C:\\Windows\\System32',
  },
  {
    name: 'Linux local Docker Engine',
    platform: 'linux',
    home: '/home/student',
    uid: 1000,
    context: 'default',
    contextHost: 'unix:///var/run/docker.sock',
    identity: { operatingSystem: 'Ubuntu 24.04', osType: 'linux', name: 'student-workstation', serverVersion: '28.5.2' },
    expectedPlatform: 'docker-engine-linux',
    expectedPath: '/usr/bin:/bin:/usr/sbin:/sbin',
  },
  {
    name: 'Linux rootless Docker Engine',
    platform: 'linux',
    home: '/home/student',
    uid: 1000,
    context: 'rootless',
    contextHost: 'unix:///run/user/1000/docker.sock',
    identity: { operatingSystem: 'Ubuntu 24.04', osType: 'linux', name: 'student-workstation', serverVersion: '28.5.2' },
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
      gid: scenario.platform === 'darwin' ? 20 : 1000,
      groups: scenario.platform === 'linux' && scenario.context === 'default' ? [999] : [20, 1000],
      repositoryRoot: root,
      env: {},
      findDocker: () => scenario.platform === 'win32' ? 'C:\\trusted\\docker.exe' : '/trusted/docker',
      lstat: () => scenario.platform === 'linux' && scenario.context === 'default'
        ? socketStat(0, 999, 0o140660)
        : socketStat(scenario.uid, scenario.platform === 'darwin' ? 20 : scenario.uid),
      spawn: platformSpawn(calls, scenario),
    });

    assert.deepEqual(result, { ok: true, platform: scenario.expectedPlatform, message: `Platform ready: ${scenario.expectedPlatform}` });
    assert.equal(calls.length, 8);
    assert.deepEqual(calls[0].argv, ['context', 'show']);
    assert.deepEqual(calls[1].argv, [
      'context', 'inspect', scenario.context, '--format', '{{json .Endpoints.docker.Host}}',
    ]);
    assert.deepEqual(calls[2].argv, ['--context', scenario.context, 'info', '--format', INFO_FORMAT]);
    assert.deepEqual(calls[3].argv, ['--context', scenario.context, 'version', '--format', VERSION_FORMAT]);
    assert.deepEqual(calls[4].argv, ['--context', scenario.context, 'compose', 'version', '--short']);
    assert.deepEqual(calls[5].argv, ['--context', scenario.context, 'compose', '-f', 'docker-compose.yml', 'config', '--format', 'json']);
    const upProject = calls[6].argv[calls[6].argv.indexOf('--project-name') + 1];
    const downProject = calls[7].argv[calls[7].argv.indexOf('--project-name') + 1];
    assert.match(upProject, /^secure-learn-doctor-[a-f0-9]{16}$/u);
    assert.equal(downProject, upProject);
    assert.deepEqual(calls[6].argv, ['--context', scenario.context, 'compose', '--project-name', upProject, '-f', 'scripts/docker-doctor.compose.yml', 'up', '--abort-on-container-exit', '--exit-code-from', 'interface-probe']);
    assert.deepEqual(calls[7].argv, ['--context', scenario.context, 'compose', '--project-name', upProject, '-f', 'scripts/docker-doctor.compose.yml', 'down', '--volumes', '--remove-orphans']);
    for (const call of calls) {
      assert.equal(call.options.cwd, root);
      assert.equal(call.options.shell, false);
      const expectedTimeout = call.argv.includes('up') ? 120_000 : call.argv.includes('down') ? 30_000 : 15_000;
      assert.equal(call.options.timeout, expectedTimeout);
      assert.equal(call.options.maxBuffer, 64 * 1024);
      assert.equal(call.options.env.PATH, scenario.expectedPath);
      assert.equal(call.options.env.DOCKER_CLI_HINTS, 'false');
      assert.equal(call.options.env.HOME, scenario.home);
      assert.equal(Object.hasOwn(call.options.env, 'DOCKER_HOST'), false);
      assert.equal(Object.hasOwn(call.options.env, 'DOCKER_CONTEXT'), false);
    }
  });
}

function macOptions(overrides = {}) {
  const calls = [];
  return {
    calls,
    options: {
      platform: 'darwin',
      home: '/Users/student',
      uid: 501,
      gid: 20,
      groups: [20],
      env: {},
      repositoryRoot: root,
      findDocker: () => '/trusted/docker',
      lstat: () => socketStat(501, 20),
      spawn: platformSpawn(calls, cases[0]),
      ...overrides,
    },
  };
}

test('Compose versions are compared as numeric semver at the 2.36.0 boundary', () => {
  assert.deepEqual(parseComposeVersion('2.36.0'), [2, 36, 0]);
  assert.deepEqual(parseComposeVersion('5.1.4'), [5, 1, 4]);
  for (const value of ['2.35.99', '2.9.100', '2.36', '2.36.x', '02.36.0', '2.036.0', '2.36.00', 'v5.1.4', '2.36.0-rc.1', '2.36.0+build', '2.36.0 trailing', '999999999999999999.0.0']) {
    assert.equal(parseComposeVersion(value), null);
  }
});

test('Docker doctor rejects remote, ambiguous, spoofed, old, and incapable engines on every OS', () => {
  const identities = {
    darwin: { operatingSystem: 'Docker Desktop', osType: 'linux', name: 'docker-desktop', serverVersion: '29.5.3' },
    win32: { operatingSystem: 'Docker Desktop', osType: 'linux', name: 'docker-desktop', serverVersion: '29.5.3' },
    linux: { operatingSystem: 'Ubuntu 24.04', osType: 'linux', name: 'local', serverVersion: '28.5.2' },
  };
  const homes = { darwin: '/Users/student', win32: 'C:\\Users\\student', linux: '/home/student' };
  const badHosts = ['tcp://127.0.0.1:2375', 'ssh://student@host', 'https://cloud.example', 'unix:///tmp/docker.sock', 'npipe:////./pipe/ambiguous'];
  for (const platform of ['darwin', 'win32', 'linux']) {
    const base = {
      platform,
      home: homes[platform],
      uid: 1000,
      gid: 1000,
      groups: platform === 'linux' ? [999] : [20, 1000],
      env: {},
      repositoryRoot: root,
      findDocker: () => platform === 'win32' ? 'C:\\trusted\\docker.exe' : '/trusted/docker',
      lstat: () => platform === 'linux' ? socketStat(0, 999, 0o140660) : socketStat(1000, 20),
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
      { identity: { operatingSystem: 'Docker Desktop', osType: 'windows', name: 'docker-desktop', serverVersion: '29.5.3' } },
      { identity: { operatingSystem: 'Docker Desktop', osType: 'linux', name: 'remote', serverVersion: '29.5.3' } },
      { server: { apiVersion: 'unknown', os: 'linux', version: '29.5.3' } },
      { server: { apiVersion: 1.54, os: 'linux', version: '29.5.3' } },
      { server: { apiVersion: '1.54', os: 'windows', version: '29.5.3' } },
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
      env: {},
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

test('Docker target override variables fail closed before sanitized CLI execution', () => {
  for (const key of ['DOCKER_HOST', 'docker_host', ' Docker_Host ', 'DOCKER_CONTEXT', 'docker_context', '\tDocker_Context\t']) {
    let calls = 0;
    const { options } = macOptions({
      env: { [key]: key === 'DOCKER_HOST' ? '' : '   ' },
      spawn: () => { calls += 1; return { status: 0, stdout: '', stderr: '' }; },
    });
    assert.equal(checkDockerPlatform(options).ok, false, key);
    assert.equal(calls, 0, `${key} must fail before invoking Docker`);
  }
});

test('learner CLI rejects Docker target overrides including blank and alternate-case keys', () => {
  const learn = path.join(root, 'scripts', 'learn');
  for (const [key, value] of [['DOCKER_HOST', ' '], ['docker_context', 'desktop-linux'], [' Docker_Host ', 'unix:///var/run/docker.sock']]) {
    const result = spawnSync(process.execPath, [learn, 'doctor', 's1'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, [key]: value },
    });
    assert.equal(result.status, 1, key);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'Docker platform is not ready.\n');
  }
});

test('Linux context and socket must match the rootful or rootless ownership boundary exactly', () => {
  const identity = { operatingSystem: 'Ubuntu 24.04', osType: 'linux', name: 'local', serverVersion: '28.5.2' };
  for (const [context, contextHost, uid] of [
    ['default', 'unix:///run/user/1000/docker.sock', 1000],
    ['rootless', 'unix:///var/run/docker.sock', 0],
  ]) {
    const calls = [];
    const result = checkDockerPlatform({
      platform: 'linux', home: '/home/student', uid: 1000, gid: 1000, groups: [999, 1000], env: {}, repositoryRoot: root,
      findDocker: () => '/trusted/docker',
      lstat: () => socketStat(uid),
      spawn: platformSpawn(calls, { context, contextHost, identity }),
    });
    assert.equal(result.ok, false, `${context} must reject ${contextHost}`);
  }
});

test('POSIX Docker sockets accept safe 0660 group access and reject unsafe metadata', () => {
  const rootfulCalls = [];
  assert.equal(checkDockerPlatform({
    platform: 'linux', home: '/home/student', uid: 1000, gid: 1000, groups: [999], env: {},
    repositoryRoot: root, findDocker: () => '/trusted/docker',
    lstat: () => socketStat(0, 999, 0o140660),
    spawn: platformSpawn(rootfulCalls, {
      context: 'default', contextHost: 'unix:///var/run/docker.sock',
      identity: { operatingSystem: 'Ubuntu 24.04', osType: 'linux', name: 'local', serverVersion: '28.5.2' },
    }),
  }).ok, true);

  const rootlessCalls = [];
  assert.equal(checkDockerPlatform({
    platform: 'linux', home: '/home/student', uid: 1000, gid: 1000, groups: [], env: {},
    repositoryRoot: root, findDocker: () => '/trusted/docker',
    lstat: () => socketStat(1000, 1000, 0o140660),
    spawn: platformSpawn(rootlessCalls, {
      context: 'rootless', contextHost: 'unix:///run/user/1000/docker.sock',
      identity: { operatingSystem: 'Ubuntu 24.04', osType: 'linux', name: 'local', serverVersion: '28.5.2' },
    }),
  }).ok, true);

  const invalidStats = [
    { uid: 501, gid: 20, mode: 0o120700, isSocket: () => false },
    { uid: 501, gid: 20, mode: 0o100700, isSocket: () => false },
    socketStat(0, 20),
    socketStat(501, 999),
    socketStat(501, 20, 0o140777),
    socketStat(501, 999, 0o140660),
  ];
  for (const stat of invalidStats) {
    const { options } = macOptions({ lstat: () => stat });
    assert.equal(checkDockerPlatform(options).ok, false);
  }
});

test('runtime probes use invocation-scoped random projects with exact cleanup isolation', () => {
  const invocations = [macOptions(), macOptions()];
  for (const invocation of invocations) {
    invocation.options.projectName = 'secure-learn-doctor';
    invocation.options.env.SECURE_LEARN_DOCTOR_PROJECT = 'secure-learn-doctor';
    assert.equal(checkDockerPlatform(invocation.options).ok, true);
  }
  const projects = invocations.map(({ calls }) => {
    const up = calls.find(({ argv }) => argv.includes('up'));
    const down = calls.find(({ argv }) => argv.includes('down'));
    const upProject = up.argv[up.argv.indexOf('--project-name') + 1];
    const downProject = down.argv[down.argv.indexOf('--project-name') + 1];
    assert.equal(downProject, upProject);
    assert.notEqual(upProject, 'secure-learn-doctor');
    return upProject;
  });
  assert.notEqual(projects[0], projects[1]);
});

test('runtime probe delegates IPAM to Docker so concurrent projects cannot overlap fixed subnets', () => {
  const source = fs.readFileSync(path.join(root, 'scripts', 'docker-doctor.compose.yml'), 'utf8');
  assert.doesNotMatch(source, /ipv4_address|subnet:/u);
  assert.match(source, /\/sys\/class\/net\/eth0/u);
  assert.match(source, /\/sys\/class\/net\/eth1/u);
});

test('Docker Engine and API versions enforce the documented 28.1.0 and 1.49 minimums', () => {
  const versions = [
    [{ apiVersion: '1.41', os: 'linux', version: '20.10.0' }, false],
    [{ apiVersion: '1.48', os: 'linux', version: '28.1.0' }, false],
    [{ apiVersion: '1.49', os: 'linux', version: '28.0.4' }, false],
    [{ apiVersion: '1.49', os: 'linux', version: '28.1.0-rc.1' }, false],
    [{ apiVersion: '1.49', os: 'linux', version: '28.1.0' }, true],
    [{ apiVersion: '1.51', os: 'linux', version: '28.5.2' }, true],
  ];
  for (const [server, expected] of versions) {
    const calls = [];
    const result = checkDockerPlatform({
      platform: 'linux', home: '/home/student', uid: 1000, gid: 1000, groups: [999], env: {},
      repositoryRoot: root, findDocker: () => '/trusted/docker',
      lstat: () => socketStat(0, 999, 0o140660),
      spawn: platformSpawn(calls, {
        context: 'default', contextHost: 'unix:///var/run/docker.sock', server,
        identity: { operatingSystem: 'Ubuntu 24.04', osType: 'linux', name: 'local', serverVersion: server.version },
      }),
    });
    assert.equal(result.ok, expected, JSON.stringify(server));
  }
});

test('Docker Engine 28.1 and API 1.49 boundary is enforced on every supported host OS', () => {
  for (const scenario of cases) {
    for (const [server, expected] of [
      [{ apiVersion: '1.49', os: 'linux', version: '28.0.4' }, false],
      [{ apiVersion: '1.48', os: 'linux', version: '28.1.0' }, false],
      [{ apiVersion: '1.49', os: 'linux', version: '28.1.0' }, true],
    ]) {
      const identity = { ...scenario.identity, serverVersion: server.version };
      const result = checkDockerPlatform({
        platform: scenario.platform,
        home: scenario.home,
        uid: scenario.uid,
        gid: scenario.platform === 'darwin' ? 20 : 1000,
        groups: scenario.platform === 'linux' && scenario.context === 'default' ? [999] : [20, 1000],
        env: {},
        repositoryRoot: root,
        findDocker: () => scenario.platform === 'win32' ? 'C:\\trusted\\docker.exe' : '/trusted/docker',
        lstat: () => scenario.platform === 'linux' && scenario.context === 'default'
          ? socketStat(0, 999, 0o140660)
          : socketStat(scenario.uid, scenario.platform === 'darwin' ? 20 : scenario.uid),
        spawn: platformSpawn([], { ...scenario, identity, server }),
      });
      assert.equal(result.ok, expected, `${scenario.name}: ${JSON.stringify(server)}`);
    }
  }
});

test('runtime interface probe always cleans up after probe or cleanup failure', () => {
  for (const statuses of [{ runtimeStatus: 7, cleanupStatus: 0 }, { runtimeStatus: 0, cleanupStatus: 9 }]) {
    const calls = [];
    const { options } = macOptions({
      spawn: platformSpawn(calls, { ...cases[0], ...statuses }),
    });
    assert.equal(checkDockerPlatform(options).ok, false);
    assert.ok(calls.some(({ argv }) => argv.includes('up')));
    assert.ok(calls.some(({ argv }) => argv.includes('down')));
    assert.deepEqual(calls.at(-1).argv.slice(-3), ['down', '--volumes', '--remove-orphans']);
  }
});

test('Docker doctor fails closed on missing CLI, spawn errors, malformed, and oversized output', () => {
  const base = {
    platform: 'darwin',
    home: '/Users/student',
    uid: 501,
    gid: 20,
    groups: [20],
    env: {},
    repositoryRoot: root,
    findDocker: () => '/trusted/docker',
    lstat: () => socketStat(501, 20),
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

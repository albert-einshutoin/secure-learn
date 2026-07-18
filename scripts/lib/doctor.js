'use strict';

const fs = require('node:fs');
const { randomBytes } = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { assertAllowedTarget } = require('./target-policy');
const { validateVmReceipt } = require('./vm-receipt');

const DOCKER_CANDIDATES = Object.freeze({
  darwin: Object.freeze([
    '/Applications/Docker.app/Contents/Resources/bin/docker',
    '/opt/homebrew/bin/docker',
    '/usr/local/bin/docker',
    '/usr/bin/docker',
  ]),
  linux: Object.freeze([
    '/usr/bin/docker',
    '/usr/local/bin/docker',
  ]),
  win32: Object.freeze([
    'C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe',
    'C:\\Program Files\\Docker\\Docker\\resources\\bin\\com.docker.cli.exe',
  ]),
});
const DOCKER_PLATFORM_BY_OS = Object.freeze({
  darwin: 'docker-desktop-macos',
  win32: 'docker-desktop-windows',
  linux: 'docker-engine-linux',
});
const CONTEXTS_BY_OS = Object.freeze({
  darwin: Object.freeze(['desktop-linux']),
  win32: Object.freeze(['desktop-linux']),
  linux: Object.freeze(['default', 'rootless']),
});
const CONTEXT_FORMAT = '{{json .Endpoints.docker.Host}}';
const INFO_FORMAT = '{"operatingSystem":{{json .OperatingSystem}},"osType":{{json .OSType}},"name":{{json .Name}},"serverVersion":{{json .ServerVersion}}}';
const VERSION_FORMAT = '{"apiVersion":{{json .Server.APIVersion}},"os":{{json .Server.Os}},"version":{{json .Server.Version}}}';
const MAX_DOCKER_OUTPUT = 64 * 1024;
const MINIMUM_COMPOSE_VERSION = Object.freeze([2, 36, 0]);
const MINIMUM_ENGINE_VERSION = Object.freeze([20, 10, 0]);
const MINIMUM_API_VERSION = Object.freeze([1, 41]);
const PROBE_COMPOSE_FILE = 'scripts/docker-doctor.compose.yml';

function isAbsoluteForPlatform(value, platform) {
  return platform === 'win32' ? path.win32.isAbsolute(value) : path.posix.isAbsolute(value);
}

function findDockerBinary(platform = process.platform) {
  for (const candidate of DOCKER_CANDIDATES[platform] || []) {
    try {
      const resolved = fs.realpathSync(candidate);
      const stat = fs.statSync(resolved);
      fs.accessSync(resolved, fs.constants.X_OK);
      // POSIX mode bits are meaningful on macOS/Linux. Windows trust comes from
      // the fixed Program Files candidate and the host ACL rather than fake mode bits.
      const safeMode = platform === 'win32' || (stat.mode & 0o022) === 0;
      if (stat.isFile() && safeMode) return resolved;
    } catch {
      // Fixed candidates are optional. PATH lookup is intentionally forbidden.
    }
  }
  return null;
}

function commandEnvironment(dependencies) {
  if (dependencies.platform === 'win32') {
    return {
      HOME: dependencies.home,
      USERPROFILE: dependencies.home,
      PATH: 'C:\\Windows\\System32',
      DOCKER_CLI_HINTS: 'false',
    };
  }
  return {
    HOME: dependencies.home,
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    DOCKER_CLI_HINTS: 'false',
  };
}

function runDocker(binary, argv, dependencies, timeout = 15_000) {
  const result = dependencies.spawn(binary, argv, {
    cwd: dependencies.repositoryRoot,
    encoding: 'utf8',
    shell: false,
    timeout,
    maxBuffer: MAX_DOCKER_OUTPUT,
    windowsHide: true,
    env: commandEnvironment(dependencies),
  });
  if (
    result === null
    || typeof result !== 'object'
    || result.error
    || result.status !== 0
    || typeof result.stdout !== 'string'
    || typeof result.stderr !== 'string'
    || Buffer.byteLength(result.stdout, 'utf8') > MAX_DOCKER_OUTPUT
    || Buffer.byteLength(result.stderr, 'utf8') > MAX_DOCKER_OUTPUT
  ) {
    throw new Error('Docker platform is not ready.');
  }
  return result.stdout.trim();
}

function parseComposeVersion(value) {
  if (typeof value !== 'string') return null;
  const component = '(?:0|[1-9]\\d{0,5})';
  const match = new RegExp(`^(${component})\\.(${component})\\.(${component})$`, 'u').exec(value);
  if (!match) return null;
  const version = match.slice(1).map(Number);
  for (let index = 0; index < MINIMUM_COMPOSE_VERSION.length; index += 1) {
    if (version[index] > MINIMUM_COMPOSE_VERSION[index]) return version;
    if (version[index] < MINIMUM_COMPOSE_VERSION[index]) return null;
  }
  return version;
}

function expectedContextHost(dependencies, context) {
  if (dependencies.platform === 'darwin') {
    if (!path.posix.isAbsolute(dependencies.home)) return null;
    return `unix://${dependencies.home}/.docker/run/docker.sock`;
  }
  if (dependencies.platform === 'win32') {
    if (!path.win32.isAbsolute(dependencies.home)) return null;
    return 'npipe:////./pipe/dockerDesktopLinuxEngine';
  }
  if (dependencies.platform === 'linux') {
    if (context === 'default') return 'unix:///var/run/docker.sock';
    if (context === 'rootless' && Number.isSafeInteger(dependencies.uid) && dependencies.uid >= 0) {
      return `unix:///run/user/${dependencies.uid}/docker.sock`;
    }
  }
  return null;
}

function contextIsLocal(contextHost, dependencies, context) {
  return contextHost === expectedContextHost(dependencies, context);
}

function hasDockerTargetOverride(env) {
  if (env === null || typeof env !== 'object') return true;
  return Object.keys(env).some((key) => {
    const normalized = key.trim().toUpperCase();
    return normalized === 'DOCKER_HOST' || normalized === 'DOCKER_CONTEXT';
  });
}

function socketMetadataMatches(contextHost, dependencies, context) {
  if (dependencies.platform === 'win32') return true;
  if (!contextHost.startsWith('unix://')) return false;
  const socketPath = contextHost.slice('unix://'.length);
  const expectedUid = dependencies.platform === 'linux' && context === 'default' ? 0 : dependencies.uid;
  if (!Number.isSafeInteger(expectedUid) || expectedUid < 0
    || !Number.isSafeInteger(dependencies.uid) || dependencies.uid < 0
    || !Number.isSafeInteger(dependencies.gid) || dependencies.gid < 0
    || !Array.isArray(dependencies.groups)
    || dependencies.groups.some((group) => !Number.isSafeInteger(group) || group < 0)) return false;
  const stat = dependencies.lstat(socketPath);
  if (!(stat !== null
    && typeof stat === 'object'
    && typeof stat.isSocket === 'function'
    && stat.isSocket()
    && stat.uid === expectedUid
    && Number.isSafeInteger(stat.gid)
    && Number.isInteger(stat.mode)
    && (stat.mode & 0o002) === 0)) return false;

  const callerGroups = new Set([dependencies.gid, ...dependencies.groups]);
  if (!callerGroups.has(stat.gid)) return false;
  if (stat.uid === dependencies.uid) return (stat.mode & 0o200) !== 0;
  return (stat.mode & 0o020) !== 0;
}

function identityMatches(identity, platform) {
  const boundedText = (value) => typeof value === 'string'
    && value.length > 0
    && value.length <= 255
    && !/[\u0000-\u001F\u007F-\u009F]/u.test(value);
  if (
    identity === null
    || typeof identity !== 'object'
    || Array.isArray(identity)
    || Object.keys(identity).sort().join(',') !== 'name,operatingSystem,osType,serverVersion'
    || !boundedText(identity.operatingSystem)
    || !boundedText(identity.name)
    || typeof identity.serverVersion !== 'string'
    || identity.operatingSystem.length === 0
    || identity.name.length === 0
    || identity.osType !== 'linux'
  ) return false;

  if (platform === 'darwin' || platform === 'win32') {
    return identity.operatingSystem === 'Docker Desktop' && identity.name === 'docker-desktop';
  }
  // Linux Docker Desktop is a different product boundary; Linux labs support
  // only the local/rootless Engine sockets enumerated above.
  return platform === 'linux' && identity.operatingSystem !== 'Docker Desktop';
}

function serverMatches(server, identity) {
  return server !== null
    && typeof server === 'object'
    && !Array.isArray(server)
    && Object.keys(server).sort().join(',') === 'apiVersion,os,version'
    && typeof server.apiVersion === 'string'
    && typeof server.os === 'string'
    && typeof server.version === 'string'
    && versionAtLeast(parseNumericVersion(server.apiVersion, 2), MINIMUM_API_VERSION)
    && server.os === 'linux'
    && versionAtLeast(parseNumericVersion(server.version, 3, true), MINIMUM_ENGINE_VERSION)
    && server.version === identity.serverVersion;
}

function parseNumericVersion(value, components, allowBuild = false) {
  if (typeof value !== 'string') return null;
  const part = '(?:0|[1-9]\\d{0,5})';
  const suffix = allowBuild ? '(?:\\+[0-9A-Za-z.-]+)?' : '';
  const match = new RegExp(`^${Array.from({ length: components }, () => `(${part})`).join('\\.')}${suffix}$`, 'u').exec(value);
  return match ? match.slice(1, components + 1).map(Number) : null;
}

function versionAtLeast(actual, minimum) {
  if (!actual || actual.length !== minimum.length) return false;
  for (let index = 0; index < minimum.length; index += 1) {
    if (actual[index] > minimum[index]) return true;
    if (actual[index] < minimum[index]) return false;
  }
  return true;
}

function hasInterfaceNameCapability(config) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) return false;
  const networks = config.services?.['target-netns']?.networks;
  return networks !== null
    && typeof networks === 'object'
    && networks.app_net?.interface_name === 'eth0'
    && networks.data_net?.interface_name === 'eth1';
}

function runInterfaceProbe(binary, context, projectName, dependencies) {
  const prefix = [
    '--context', context, 'compose', '--project-name', projectName,
    '-f', PROBE_COMPOSE_FILE,
  ];
  let probeError;
  try {
    runDocker(binary, [
      ...prefix, 'up', '--abort-on-container-exit', '--exit-code-from', 'interface-probe',
    ], dependencies, 120_000);
  } catch (error) {
    probeError = error;
  } finally {
    try {
      runDocker(binary, [...prefix, 'down', '--volumes', '--remove-orphans'], dependencies, 30_000);
    } catch (cleanupError) {
      probeError = cleanupError;
    }
  }
  if (probeError) throw probeError;
}

function checkDockerPlatform(options = {}) {
  const platform = options.platform || process.platform;
  const dependencies = {
    platform,
    home: options.home || os.homedir(),
    uid: options.uid ?? (typeof process.getuid === 'function' ? process.getuid() : null),
    gid: options.gid ?? (typeof process.getgid === 'function' ? process.getgid() : null),
    groups: options.groups ?? (typeof process.getgroups === 'function' ? process.getgroups() : []),
    env: options.env || process.env,
    repositoryRoot: options.repositoryRoot || fs.realpathSync(path.resolve(__dirname, '../..')),
    findDocker: options.findDocker || (() => findDockerBinary(platform)),
    lstat: options.lstat || fs.lstatSync,
    spawn: options.spawn || spawnSync,
  };
  const failure = { ok: false, message: 'Docker platform is not ready.' };
  const platformId = DOCKER_PLATFORM_BY_OS[platform];
  const allowedContexts = CONTEXTS_BY_OS[platform];
  if (!platformId || !allowedContexts) return failure;
  if (hasDockerTargetOverride(dependencies.env)) return failure;

  const binary = dependencies.findDocker();
  if (typeof binary !== 'string' || !isAbsoluteForPlatform(binary, platform)) return failure;

  try {
    // Validate the active context because learners subsequently invoke plain
    // `docker compose`; checking an unused local context would not bound that command.
    const context = runDocker(binary, ['context', 'show'], dependencies);
    if (!allowedContexts.includes(context)) return failure;

    const contextOutput = runDocker(binary, [
      'context', 'inspect', context, '--format', CONTEXT_FORMAT,
    ], dependencies);
    const contextHost = JSON.parse(contextOutput);
    if (!contextIsLocal(contextHost, dependencies, context)) return failure;
    if (!socketMetadataMatches(contextHost, dependencies, context)) return failure;

    const infoOutput = runDocker(binary, [
      '--context', context, 'info', '--format', INFO_FORMAT,
    ], dependencies);
    const identity = JSON.parse(infoOutput);
    if (!identityMatches(identity, platform)) return failure;

    const serverOutput = runDocker(binary, [
      '--context', context, 'version', '--format', VERSION_FORMAT,
    ], dependencies);
    if (!serverMatches(JSON.parse(serverOutput), identity)) return failure;

    const versionOutput = runDocker(binary, [
      '--context', context, 'compose', 'version', '--short',
    ], dependencies);
    if (!parseComposeVersion(versionOutput)) return failure;

    const configOutput = runDocker(binary, [
      '--context', context, 'compose', '-f', 'docker-compose.yml', 'config', '--format', 'json',
    ], dependencies);
    if (!hasInterfaceNameCapability(JSON.parse(configOutput))) return failure;
    // A per-invocation project prevents one doctor cleanup from targeting a
    // concurrent probe or a pre-existing project with a predictable name.
    const projectName = `secure-learn-doctor-${randomBytes(8).toString('hex')}`;
    runInterfaceProbe(binary, context, projectName, dependencies);
  } catch {
    // Docker output and errors may contain environment data; never reflect it.
    return failure;
  }

  return { ok: true, platform: platformId, message: `Platform ready: ${platformId}` };
}

function validateSafetyBoundary(safety) {
  for (const service of safety.target_services) assertAllowedTarget(service, safety);
  for (const cidr of safety.allowed_cidrs) assertAllowedTarget(cidr.split('/')[0], safety);
}

function safetyOutput(safety) {
  return [
    `Allowed services: ${safety.target_services.length > 0 ? safety.target_services.join(',') : 'none'}`,
    `Allowed CIDRs: ${safety.allowed_cidrs.length > 0 ? safety.allowed_cidrs.join(',') : 'none'}`,
    `External network: ${safety.external_network ? 'enabled' : 'disabled'}`,
  ].join('\n');
}

function doctorManifest(manifest, options = {}) {
  const platform = options.platform || process.platform;
  const env = options.env || process.env;
  const repositoryRoot = options.repositoryRoot || fs.realpathSync(path.resolve(__dirname, '../..'));
  const checkDocker = options.checkDocker || checkDockerPlatform;
  const validateReceipt = options.validateReceipt || validateVmReceipt;

  validateSafetyBoundary(manifest.safety);
  if (manifest.platforms.required.includes('linux-vm')) {
    if (manifest.platforms.required.length !== 1 || manifest.platforms.optional.length !== 0) {
      throw new Error('Linux VM platform cannot be combined with Docker platforms.');
    }
    if (platform !== 'linux') throw new Error('Linux VM lab must be checked from a Linux VM.');
    validateReceipt(env.SECURE_LEARN_VM_RECEIPT, {
      repositoryRoot,
      expectedLabId: manifest.id,
    });
    return `Platform ready: linux-vm (operator-attested local VM receipt)\n${safetyOutput(manifest.safety)}\n`;
  }

  const expectedPlatform = DOCKER_PLATFORM_BY_OS[platform];
  if (!expectedPlatform || !manifest.platforms.required.includes(expectedPlatform)) {
    throw new Error('Current Docker platform is not declared by this lab.');
  }
  const result = checkDocker({ platform, repositoryRoot, env });
  if (!result.ok || result.platform !== expectedPlatform) throw new Error('Docker platform is not ready.');
  return `${result.message}\n${safetyOutput(manifest.safety)}\n`;
}

module.exports = {
  checkDockerPlatform,
  doctorManifest,
  INFO_FORMAT,
  parseComposeVersion,
  VERSION_FORMAT,
};

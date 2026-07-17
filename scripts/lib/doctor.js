'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { assertAllowedTarget } = require('./target-policy');
const { validateVmReceipt } = require('./vm-receipt');

const DOCKER_CANDIDATES = [
  '/Applications/Docker.app/Contents/Resources/bin/docker',
  '/opt/homebrew/bin/docker',
  '/usr/local/bin/docker',
  '/usr/bin/docker',
];
const CONTEXT_FORMAT = '{{json .Endpoints.docker.Host}}';
const INFO_FORMAT = '{"operatingSystem":{{json .OperatingSystem}},"osType":{{json .OSType}},"name":{{json .Name}}}';
const MAX_DOCKER_OUTPUT = 64 * 1024;

function findDockerBinary() {
  for (const candidate of DOCKER_CANDIDATES) {
    try {
      const resolved = fs.realpathSync(candidate);
      const stat = fs.statSync(resolved);
      fs.accessSync(resolved, fs.constants.X_OK);
      if (stat.isFile() && (stat.mode & 0o022) === 0) return resolved;
    } catch {
      // Fixed candidates are optional. PATH lookup is intentionally forbidden.
    }
  }
  return null;
}

function runDocker(binary, argv, dependencies) {
  const result = dependencies.spawn(binary, argv, {
    cwd: dependencies.repositoryRoot,
    encoding: 'utf8',
    shell: false,
    timeout: 15_000,
    maxBuffer: MAX_DOCKER_OUTPUT,
    windowsHide: true,
    env: {
      HOME: dependencies.home,
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
      DOCKER_CLI_HINTS: 'false',
    },
  });
  if (
    result === null
    || typeof result !== 'object'
    || result.error
    || result.status !== 0
    || typeof result.stdout !== 'string'
    || Buffer.byteLength(result.stdout, 'utf8') > MAX_DOCKER_OUTPUT
  ) {
    throw new Error('Docker Desktop is not ready.');
  }
  return result.stdout.trim();
}

function checkDockerDesktop(options = {}) {
  const dependencies = {
    platform: options.platform || process.platform,
    home: options.home || os.homedir(),
    repositoryRoot: options.repositoryRoot || fs.realpathSync(path.resolve(__dirname, '../..')),
    findDocker: options.findDocker || findDockerBinary,
    spawn: options.spawn || spawnSync,
  };
  const failure = { ok: false, message: 'Docker Desktop is not ready.' };
  if (dependencies.platform !== 'darwin') return failure;

  const binary = dependencies.findDocker();
  if (typeof binary !== 'string' || !path.isAbsolute(binary)) return failure;

  try {
    const contextOutput = runDocker(binary, [
      'context', 'inspect', 'desktop-linux', '--format', CONTEXT_FORMAT,
    ], dependencies);
    const contextHost = JSON.parse(contextOutput);
    if (contextHost !== `unix://${dependencies.home}/.docker/run/docker.sock`) return failure;

    const infoOutput = runDocker(binary, [
      '--context', 'desktop-linux', 'info', '--format', INFO_FORMAT,
    ], dependencies);
    const identity = JSON.parse(infoOutput);
    if (
      identity === null
      || typeof identity !== 'object'
      || Array.isArray(identity)
      || Object.keys(identity).sort().join(',') !== 'name,operatingSystem,osType'
      || identity.operatingSystem !== 'Docker Desktop'
      || identity.osType !== 'linux'
      || identity.name !== 'docker-desktop'
    ) {
      return failure;
    }
  } catch {
    // Docker output and errors may contain environment data; never reflect it.
    return failure;
  }

  return { ok: true, message: 'Platform ready: docker-desktop' };
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
  const checkDocker = options.checkDocker || checkDockerDesktop;
  const validateReceipt = options.validateReceipt || validateVmReceipt;

  validateSafetyBoundary(manifest.safety);
  const messages = [];
  for (const requiredPlatform of manifest.platforms.required) {
    if (requiredPlatform === 'docker-desktop') {
      const result = checkDocker();
      if (!result.ok) throw new Error('Docker Desktop is not ready.');
      messages.push(result.message);
    } else if (requiredPlatform === 'linux-vm') {
      if (platform !== 'linux') throw new Error('Linux VM lab must be checked from a Linux VM.');
      validateReceipt(env.SECURE_LEARN_VM_RECEIPT, {
        repositoryRoot,
        expectedLabId: manifest.id,
      });
      messages.push('Platform ready: linux-vm (operator-attested local VM receipt)');
    } else {
      throw new Error('Unsupported required platform.');
    }
  }
  return `${messages.join('\n')}\n${safetyOutput(manifest.safety)}\n`;
}

module.exports = { checkDockerDesktop, doctorManifest, INFO_FORMAT };

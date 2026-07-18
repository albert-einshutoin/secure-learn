const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const root = path.resolve(__dirname, '..');

function runProcessCounter(input) {
  return spawnSync('bash', [path.join(root, 'scripts/lib/count_publisher_processes.sh')], {
    cwd: root,
    encoding: 'utf8',
    input,
  });
}

function composeConfig(files) {
  const args = ['compose', '--profile', 'capstone'];
  for (const file of files) args.push('-f', path.join(root, file));
  args.push('config', '--format', 'json');
  const result = spawnSync('docker', args, { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function assertHardenedPublisher(service, listenPort, destination) {
  assert.equal(service.user, '65532:65532');
  assert.equal(service.read_only, true);
  assert.deepEqual(service.cap_drop, ['ALL']);
  assert.deepEqual(service.security_opt, ['no-new-privileges:true']);
  assert.deepEqual(service.sysctls, { 'net.ipv4.ip_forward': '0' });
  assert.deepEqual(service.entrypoint, ['/usr/bin/socat']);
  assert.equal(service.pids_limit, 80);
  assert.equal(service.cpus, 0.5);
  assert.equal(service.mem_limit, String(128 * 1024 * 1024));
  assert.deepEqual(service.ulimits.nofile, { soft: 256, hard: 512 });
  assert.deepEqual(service.command, [
    `TCP-LISTEN:${listenPort},fork,reuseaddr,max-children=64`,
    `TCP:${destination}`,
  ]);
}

test('base Compose uses hardened proxy-only host publishing without bridging attack and data zones', () => {
  const config = composeConfig(['docker-compose.yml']);
  const { services, networks } = config;

  assert.equal(networks.app_net.internal, true);
  assert.equal(networks.data_net.internal, true);
  assert.notEqual(networks.host_access.internal, true);

  assert.deepEqual(Object.keys(services.kali.networks), ['app_net']);
  assert.deepEqual(Object.keys(services.db.networks), ['data_net']);
  assert.deepEqual(Object.keys(services['target-netns'].networks), ['app_net', 'data_net']);
  assert.equal(services['target-netns'].networks.app_net.interface_name, 'eth0');
  assert.equal(services['target-netns'].networks.data_net.interface_name, 'eth1');
  assert.equal(services['target-netns'].sysctls['net.ipv4.ip_forward'], '0');
  assert.equal(services.kali.ports, undefined);
  assert.equal(services.db.ports, undefined);
  assert.equal(services['target-netns'].ports, undefined);

  assert.deepEqual(Object.keys(services['app-publisher'].networks), ['app_net', 'host_access']);
  assert.deepEqual(Object.keys(services['db-publisher'].networks), ['data_net', 'host_access']);
  assert.deepEqual(
    Object.entries(services)
      .filter(([, service]) => service.networks?.host_access)
      .map(([name]) => name)
      .sort(),
    ['app-publisher', 'db-publisher'],
  );
  assertHardenedPublisher(services['app-publisher'], 3000, '172.23.0.20:3000');
  assertHardenedPublisher(services['db-publisher'], 15432, '172.25.0.40:5432');
  assert.equal(services['app-publisher'].ports[0].host_ip, '127.0.0.1');
  assert.equal(services['app-publisher'].ports[0].published, '3000');
  assert.equal(services['db-publisher'].ports[0].host_ip, '127.0.0.1');
  assert.equal(services['db-publisher'].ports[0].published, '15432');
});

test('learning edge and Redis are exposed only through hardened publishers', () => {
  const config = composeConfig(['docker-compose.yml', 'docker-compose.learning.yml']);
  const { services } = config;

  assert.equal(services['learning-edge-proxy'].ports, undefined);
  assert.equal(services['learning-redis'].ports, undefined);
  assert.deepEqual(Object.keys(services['learning-edge-publisher'].networks), ['app_net', 'host_access']);
  assert.deepEqual(Object.keys(services['learning-redis-publisher'].networks), ['app_net', 'host_access']);
  assert.deepEqual(
    Object.entries(services)
      .filter(([, service]) => service.networks?.host_access)
      .map(([name]) => name)
      .sort(),
    ['app-publisher', 'db-publisher', 'learning-edge-publisher', 'learning-redis-publisher'],
  );
  assertHardenedPublisher(services['learning-edge-publisher'], 8080, '172.23.0.50:8080');
  assertHardenedPublisher(services['learning-redis-publisher'], 6380, '172.23.0.60:6379');
  assert.equal(services['learning-edge-publisher'].ports[0].host_ip, '127.0.0.1');
  assert.equal(services['learning-edge-publisher'].ports[0].published, '8080');
  assert.equal(services['learning-redis-publisher'].ports[0].host_ip, '127.0.0.1');
  assert.equal(services['learning-redis-publisher'].ports[0].published, '6380');
});

test('host publisher image is immutable, non-root, and installs no runtime dependencies', () => {
  const dockerfile = fs.readFileSync(path.join(root, 'docker/host-publisher/Dockerfile'), 'utf8');
  assert.match(dockerfile, /^FROM alpine:3\.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce$/m);
  assert.match(dockerfile, /^RUN apk add --no-cache socat=1\.8\.1\.3-r0/m);
  assert.match(dockerfile, /^USER 65532:65532$/m);
  assert.match(dockerfile, /^ENTRYPOINT \["\/usr\/bin\/socat"\]$/m);
  assert.doesNotMatch(dockerfile, /curl|wget|ENTRYPOINT \[".*sh/);
});

test('all build-time Alpine packages are pinned exactly', () => {
  const appDockerfile = fs.readFileSync(path.join(root, 'app/Dockerfile'), 'utf8');
  const publisherDockerfile = fs.readFileSync(path.join(root, 'docker/host-publisher/Dockerfile'), 'utf8');
  const ipsDockerfile = fs.readFileSync(path.join(root, 'docker/ips-iptables/Dockerfile'), 'utf8');

  assert.match(appDockerfile, /^RUN apk add --no-cache su-exec=0\.3-r0/m);
  assert.match(publisherDockerfile, /^RUN apk add --no-cache socat=1\.8\.1\.3-r0/m);
  assert.match(ipsDockerfile, /^RUN apk add --no-cache iptables=1\.8\.11-r1$/m);
});

test('publisher process counter parses portable docker top output and fails closed', () => {
  const linux = runProcessCounter('PID PPID COMMAND\n100 0 socat\n101 100 socat\n102 100 socat\n');
  assert.equal(linux.status, 0, linux.stderr);
  assert.equal(linux.stdout, '3 2\n');

  const spaced = runProcessCounter('  PID   PPID   COMMAND\n  200   0      socat\n  201   200    socat\n');
  assert.equal(spaced.status, 0, spaced.stderr);
  assert.equal(spaced.stdout, '2 1\n');

  for (const invalid of [
    '',
    'PID PPID COMMAND\n',
    'PID PPID COMMAND\nabc 0 socat\n',
    'PID PPID COMMAND\n100 0 sh\n',
    'PID PPID COMMAND\n100 0 socat\n101 100 sleep\n',
  ]) {
    assert.notEqual(runProcessCounter(invalid).status, 0, `accepted ${JSON.stringify(invalid)}`);
  }
});

test('publisher pressure gate uses Kali bash FDs and host-side sampled docker top evidence', () => {
  const freshStack = fs.readFileSync(path.join(root, 'scripts/fresh_stack_e2e.sh'), 'utf8');

  assert.doesNotMatch(freshStack, /exec -T app-publisher[^\n]*\/proc|publisher_connection_limit_probe\.js/);
  assert.match(freshStack, /docker top "\$container_id" -eo pid,ppid,comm/);
  assert.match(freshStack, /count_publisher_processes\.sh/);
  assert.match(freshStack, /exec -T kali bash/);
  assert.match(freshStack, /\/dev\/tcp\/172\.23\.0\.10\/3000/);
  assert.match(freshStack, /requested=70/);
  assert.match(freshStack, /seq 1 5/);
  assert.match(freshStack, /max_publisher_pids <= 80/);
  assert.match(freshStack, /max_publisher_children <= 64/);
  assert.match(freshStack, /max_publisher_children >= 10/);
  assert.match(freshStack, /opened_connections >= 65/);
  assert.match(freshStack, /Application after publisher pressure/);
  assert.match(freshStack, /"samples":\[/);
  assert.match(freshStack, /"recovered":true/);
});

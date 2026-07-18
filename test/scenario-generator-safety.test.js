const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const test = require('node:test');
const { inspect } = require('node:util');

const generator = require('../scripts/generate_scenario_html');

test('manifest mode is the only effective mode when a manifest exists', () => {
  assert.equal(generator.resolveEffectiveMode({
    manifestMode: 'docker-lab',
    scenarioMode: 'host-assisted',
    scenarioNumber: 5,
  }), 'docker-lab');
});

test('safe publisher refuses symlinks and non-regular destinations before writing', (t) => {
  const fixture = makeFixture(t);
  const external = path.join(fixture.base, 'external.txt');
  fs.writeFileSync(external, 'unchanged');
  fs.symlinkSync(external, path.join(fixture.outDir, 'index.html'));

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs: new Map([['index.html', 'replacement']]),
    allowedPaths: new Set(['index.html']),
  }), /symlink|regular file/i);
  assert.equal(fs.readFileSync(external, 'utf8'), 'unchanged');
  assert.equal(fs.readdirSync(fixture.outDir).some((name) => name.includes('.tmp')), false);
});

test('safe publisher stages every output before transactional publication', (t) => {
  const fixture = makeFixture(t);
  fs.writeFileSync(path.join(fixture.outDir, 'index.html'), 'old');
  fs.mkdirSync(path.join(fixture.assetDir, 'scenario.css'));

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs: new Map([['index.html', 'new'], ['assets/scenario.css', Buffer.from('css')]]),
    allowedPaths: new Set(['index.html', 'assets/scenario.css']),
  }), /regular file/i);
  assert.equal(fs.readFileSync(path.join(fixture.outDir, 'index.html'), 'utf8'), 'old');
});

test('safe publisher writes deterministic content with explicit file mode', (t) => {
  const fixture = makeFixture(t);
  generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs: new Map([['index.html', 'hello'], ['assets/scenario.css', Buffer.from('css')]]),
    allowedPaths: new Set(['index.html', 'assets/scenario.css']),
  });

  assert.equal(fs.readFileSync(path.join(fixture.outDir, 'index.html'), 'utf8'), 'hello');
  assert.equal(fs.readFileSync(path.join(fixture.assetDir, 'scenario.css'), 'utf8'), 'css');
  assert.equal(fs.statSync(path.join(fixture.outDir, 'index.html')).mode & 0o777, 0o644);
});

test('safe publisher bootstraps only the expected directory chain', (t) => {
  const fixture = makeFixture(t, { createOutputTree: false });

  generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs: new Map([['index.html', 'hello'], ['assets/scenario.css', 'css']]),
    allowedPaths: new Set(['index.html', 'assets/scenario.css']),
  });

  assert.equal(fs.readFileSync(path.join(fixture.outDir, 'index.html'), 'utf8'), 'hello');
  assert.equal(fs.readFileSync(path.join(fixture.assetDir, 'scenario.css'), 'utf8'), 'css');
});

test('safe publisher rejects a symlink in a bootstrapped directory segment', (t) => {
  const fixture = makeFixture(t, { createOutputTree: false });
  const external = path.join(fixture.base, 'external');
  fs.mkdirSync(external);
  fs.symlinkSync(external, path.join(fixture.root, 'docs'));

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs: new Map([['index.html', 'hello']]),
    allowedPaths: new Set(['index.html']),
  }), /symlink/i);
  assert.deepEqual(fs.readdirSync(external), []);
});

test('safe publisher accepts only the fixed scenario-guide output chain', (t) => {
  const fixture = makeFixture(t, { createOutputTree: false });
  const unexpected = path.join(fixture.root, 'docs', 'other-output');

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: unexpected,
    outputs: new Map([['index.html', 'hello']]),
    allowedPaths: new Set(['index.html']),
  }), /fixed|scenario-guides|output directory/i);
  assert.equal(fs.existsSync(unexpected), false);
});

test('safe publisher enforces 0644 under a restrictive process umask', (t) => {
  const fixture = makeFixture(t);
  const previous = process.umask(0o077);
  try {
    generator.safePublishOutputs({
      root: fixture.root,
      outDir: fixture.outDir,
      outputs: new Map([['index.html', 'hello']]),
      allowedPaths: new Set(['index.html']),
    });
  } finally {
    process.umask(previous);
  }

  assert.equal(fs.statSync(path.join(fixture.outDir, 'index.html')).mode & 0o777, 0o644);
});

test('safe publisher fails closed on an existing writer lock before staging', (t) => {
  const fixture = makeFixture(t);
  const destination = path.join(fixture.outDir, 'index.html');
  const lock = path.join(fixture.outDir, '.scenario-generator.lock');
  fs.writeFileSync(destination, 'old');
  fs.writeFileSync(lock, 'other writer');

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs: new Map([['index.html', 'new']]),
    allowedPaths: new Set(['index.html']),
  }), /another writer|stale lock/i);
  assert.equal(fs.readFileSync(destination, 'utf8'), 'old');
  assert.deepEqual(generatedArtifacts(fixture.outDir), ['.scenario-generator.lock']);
});

for (const failAt of [2, 10]) {
  test(`safe publisher rolls back every file when rename ${failAt} fails`, (t) => {
    const fixture = makeFixture(t);
    const outputs = seededOutputs(fixture, 6);
    const before = snapshotOutputs(fixture.outDir, outputs.keys());
    let renames = 0;

    assert.throws(() => generator.safePublishOutputs({
      root: fixture.root,
      outDir: fixture.outDir,
      outputs,
      allowedPaths: new Set(outputs.keys()),
      operations: {
        renameSync(...args) {
          renames += 1;
          if (renames === failAt) throw Object.assign(new Error(`rename fault ${failAt}`), { code: 'EIO' });
          return fs.renameSync(...args);
        },
      },
    }), new RegExp(`rename fault ${failAt}`));

    assert.deepEqual(snapshotOutputs(fixture.outDir, outputs.keys()), before);
    assert.deepEqual(generatedArtifacts(fixture.outDir), []);
  });
}

test('safe publisher rolls back published files when directory fsync fails', (t) => {
  const fixture = makeFixture(t);
  const outputs = seededOutputs(fixture, 3);
  const before = snapshotOutputs(fixture.outDir, outputs.keys());

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs,
    allowedPaths: new Set(outputs.keys()),
    operations: {
      fsyncSync() {
        throw Object.assign(new Error('fsync fault'), { code: 'EIO' });
      },
    },
  }), /fsync fault/);

  assert.deepEqual(snapshotOutputs(fixture.outDir, outputs.keys()), before);
  assert.deepEqual(generatedArtifacts(fixture.outDir), []);
});

test('safe publisher fails closed when committed backup cleanup is incomplete', (t) => {
  const fixture = makeFixture(t);
  const outputs = seededOutputs(fixture, 1);
  fs.writeFileSync(path.join(fixture.assetDir, 'scenario.css'), 'old-css');
  const assetFirstOutputs = new Map([
    ['assets/scenario.css', 'new-css'],
    ...outputs,
  ]);
  let cleanupAttempts = 0;

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs: assetFirstOutputs,
    allowedPaths: new Set(assetFirstOutputs.keys()),
    operations: {
      unlinkSync(candidate) {
        cleanupAttempts += 1;
        if (cleanupAttempts === 2) throw Object.assign(new Error('unlink fault'), { code: 'EIO' });
        return fs.unlinkSync(candidate);
      },
    },
  }), /page-0\.html.*\.backup/i);

  for (const [relative, content] of assetFirstOutputs) {
    assert.equal(fs.readFileSync(path.join(fixture.outDir, relative), 'utf8'), content);
  }
  assert.ok(generatedArtifacts(fixture.outDir).some((name) => name.endsWith('.backup')));
  let retryError;
  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs: assetFirstOutputs,
    allowedPaths: new Set(assetFirstOutputs.keys()),
  }), (error) => {
    retryError = error;
    return true;
  });
  assert.match(retryError.message, /remaining artifact count=1/i);
  assert.doesNotMatch(retryError.message, /page-0|scenario\.css|\.backup/i);
});

test('safe publisher preserves the failed cleanup target when unlink races with artifact removal', (t) => {
  const fixture = makeFixture(t);
  const outputs = seededOutputs(fixture, 1);
  let removedBackup;
  let diagnostic;

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs,
    allowedPaths: new Set(outputs.keys()),
    operations: {
      unlinkSync(candidate) {
        removedBackup = path.relative(fs.realpathSync(fixture.outDir), candidate);
        fs.unlinkSync(candidate);
        throw Object.assign(new Error('sensitive cleanup detail must not be reflected'), { code: 'EIO' });
      },
    },
  }), (error) => {
    diagnostic = error;
    return true;
  });

  assert.ok(removedBackup.endsWith('.backup'));
  assert.match(diagnostic.message, /backup cleanup failed at unlink/i);
  assert.match(diagnostic.message, new RegExp(escapeRegExp(removedBackup)));
  assert.match(diagnostic.message, /EIO/);
  assert.doesNotMatch(diagnostic.message, /sensitive cleanup detail/);
  assert.doesNotMatch(diagnostic.message, /unknown artifact/i);
  assert.equal(diagnostic.cause, undefined);
  assert.doesNotMatch(inspect(diagnostic), /sensitive cleanup detail/);
  assert.deepEqual(generatedArtifacts(fixture.outDir), []);
  assert.equal(fs.readFileSync(path.join(fixture.outDir, 'page-0.html'), 'utf8'), 'new-0');
});

test('cleanup diagnostics sanitize unknown error codes across child stderr', (t) => {
  const childSource = `
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const generator = require(${JSON.stringify(path.join(__dirname, '..', 'scripts', 'generate_scenario_html.js'))});
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'scenario-child-'));
const root = path.join(base, 'repo');
const outDir = path.join(root, 'docs', 'scenario-guides');
fs.mkdirSync(path.join(outDir, 'assets'), { recursive: true });
fs.writeFileSync(path.join(outDir, 'index.html'), 'old');
try {
  generator.safePublishOutputs({
    root,
    outDir,
    outputs: new Map([['index.html', 'new']]),
    allowedPaths: new Set(['index.html']),
    operations: { unlinkSync() {
      throw Object.assign(new Error('child-secret-path=/private/token'), { code: '\\u001b[31mSECRET_CODE' });
    } },
  });
} catch (error) {
  console.error(error);
} finally {
  fs.rmSync(base, { recursive: true, force: true });
}
`;
  const run = spawnSync(process.execPath, ['-e', childSource], { encoding: 'utf8', maxBuffer: 4096 });
  t.after(() => assert.equal(run.error, undefined));

  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stderr, /backup cleanup failed at unlink.*\(UNKNOWN\)/i);
  assert.doesNotMatch(run.stderr, /child-secret|private\/token|SECRET_CODE|\u001b/i);
  assert.ok(Buffer.byteLength(run.stderr) <= 1024, `stderr was ${Buffer.byteLength(run.stderr)} bytes`);
});

test('cleanup diagnostics identify the nth failed backup and count only remaining artifacts', (t) => {
  const fixture = makeFixture(t);
  const outputs = seededOutputs(fixture, 3);
  const attempted = [];
  let diagnostic;

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs,
    allowedPaths: new Set(outputs.keys()),
    operations: {
      unlinkSync(candidate) {
        attempted.push(path.relative(fs.realpathSync(fixture.outDir), candidate));
        fs.unlinkSync(candidate);
        if (attempted.length === 2) throw Object.assign(new Error('nth secret'), { code: 'EIO' });
      },
    },
  }), (error) => {
    diagnostic = error;
    return true;
  });

  assert.equal(attempted.length, 2);
  assert.match(diagnostic.message, new RegExp(escapeRegExp(attempted[1])));
  assert.doesNotMatch(diagnostic.message, new RegExp(escapeRegExp(attempted[0])));
  assert.match(diagnostic.message, /remaining artifact count=1/i);
  assert.equal(generatedArtifacts(fixture.outDir).filter((name) => name.endsWith('.backup')).length, 1);
});

test('assets-only cleanup diagnostics retain a safe relative target', (t) => {
  const fixture = makeFixture(t);
  const destination = path.join(fixture.assetDir, 'scenario.css');
  fs.writeFileSync(destination, 'old');
  let diagnostic;

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs: new Map([['assets/scenario.css', 'new']]),
    allowedPaths: new Set(['assets/scenario.css']),
    operations: {
      unlinkSync(candidate) {
        fs.unlinkSync(candidate);
        throw Object.assign(new Error('asset secret'), { code: 'EIO' });
      },
    },
  }), (error) => {
    diagnostic = error;
    return true;
  });

  assert.match(diagnostic.message, /for assets\/\.scenario\.css\.[a-f0-9.-]+\.backup \(EIO\)/i);
  assert.match(diagnostic.message, /remaining artifact count=0/i);
  assert.doesNotMatch(inspect(diagnostic), /asset secret/i);
});

test('ENOENT after backup removal is treated as a completed cleanup race', (t) => {
  const fixture = makeFixture(t);
  const outputs = seededOutputs(fixture, 1);

  generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs,
    allowedPaths: new Set(outputs.keys()),
    operations: {
      unlinkSync(candidate) {
        fs.unlinkSync(candidate);
        throw Object.assign(new Error('already gone'), { code: 'ENOENT' });
      },
    },
  });

  assert.deepEqual(generatedArtifacts(fixture.outDir), []);
  assert.equal(fs.readFileSync(path.join(fixture.outDir, 'page-0.html'), 'utf8'), 'new-0');
});

test('artifact recovery scans expose only bounded counts', (t) => {
  const fixture = makeFixture(t);
  const ansiArtifact = '.artifact-\u001b[31msecret.backup';
  const oversizedArtifact = `.${'x'.repeat(246)}.backup`;
  fs.writeFileSync(path.join(fixture.outDir, ansiArtifact), 'artifact');
  fs.writeFileSync(path.join(fixture.assetDir, oversizedArtifact), 'artifact');
  let diagnostic;

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs: new Map([['index.html', 'new']]),
    allowedPaths: new Set(['index.html']),
  }), (error) => {
    diagnostic = error;
    return true;
  });

  assert.match(diagnostic.message, /remaining artifact count=2/i);
  assert.doesNotMatch(diagnostic.message, /artifact-|secret|x{16}|\u001b/i);
});

test('artifact recovery scan count is capped', (t) => {
  const fixture = makeFixture(t);
  for (let index = 0; index < 70; index += 1) {
    fs.writeFileSync(path.join(fixture.outDir, `.artifact-${index}.backup`), 'artifact');
  }

  assert.throws(() => generator.safePublishOutputs({
    root: fixture.root,
    outDir: fixture.outDir,
    outputs: new Map([['index.html', 'new']]),
    allowedPaths: new Set(['index.html']),
  }), /remaining artifact count=64\+/i);
});

for (const stage of ['lstat', 'opendir', 'read', 'close']) {
  test(`initial recovery ${stage} failure is sanitized and fails closed`, (t) => {
    const fixture = makeFixture(t);
    const injected = makeScanFailureOperations(stage, 1);
    let diagnostic;

    assert.throws(() => generator.safePublishOutputs({
      root: fixture.root,
      outDir: fixture.outDir,
      outputs: new Map([['index.html', 'new']]),
      allowedPaths: new Set(['index.html']),
      operations: injected.operations,
    }), (error) => {
      diagnostic = error;
      return true;
    });

    assert.match(diagnostic.message, /recovery scan unavailable.*refusing/i);
    assert.doesNotMatch(inspect(diagnostic), /scan-secret|private\/scan-path|\u001b/i);
    assert.deepEqual(generatedArtifacts(fixture.outDir), []);
    assert.equal(fs.existsSync(path.join(fixture.outDir, 'index.html')), false);
    if (stage === 'read') assert.equal(injected.closeAttempts(), 1);
  });

  test(`cleanup recovery ${stage} failure preserves the unlink diagnostic`, (t) => {
    const fixture = makeFixture(t);
    const outputs = seededOutputs(fixture, 1);
    const injected = makeScanFailureOperations(stage, 3);
    let failedBackup;
    let diagnostic;

    assert.throws(() => generator.safePublishOutputs({
      root: fixture.root,
      outDir: fixture.outDir,
      outputs,
      allowedPaths: new Set(outputs.keys()),
      operations: {
        ...injected.operations,
        unlinkSync(candidate) {
          failedBackup = path.relative(fs.realpathSync(fixture.outDir), candidate);
          fs.unlinkSync(candidate);
          throw Object.assign(new Error('unlink-secret'), { code: 'EIO' });
        },
      },
    }), (error) => {
      diagnostic = error;
      return true;
    });

    assert.match(diagnostic.message, /backup cleanup failed at unlink/i);
    assert.match(diagnostic.message, new RegExp(escapeRegExp(failedBackup)));
    assert.match(diagnostic.message, /\(EIO\)/);
    assert.match(diagnostic.message, /remaining artifact scan=unavailable/i);
    assert.doesNotMatch(inspect(diagnostic), /scan-secret|unlink-secret|private\/scan-path|\u001b/i);
    assert.equal(fs.readFileSync(path.join(fixture.outDir, 'page-0.html'), 'utf8'), 'new-0');
    if (stage === 'read') assert.equal(injected.closeAttempts(), 1);
  });
}

test('S7 records an nmap exit 7 and continues the bounded event report', (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 's7-nonzero-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const bin = path.join(base, 'bin');
  const results = path.join(base, 'results');
  fs.mkdirSync(bin);
  writeExecutable(path.join(bin, 'nmap'), '#!/bin/sh\necho "bounded scan output"\nexit 7\n');
  writeExecutable(path.join(bin, 'jq'), '#!/bin/sh\ncat\n');
  writeExecutable(path.join(bin, 'curl'), `#!/bin/sh
case " $* " in
  *" -o /dev/null "*) printf '429' ;;
  *" -I "*) printf 'HTTP/1.1 301 redirect-secret\\r\\nLocation: /next\\r\\nHTTP/2 200 super-secret-reason\\r\\nSet-Cookie: token=cookie-secret\\r\\nX-Probe: \\033[31mansi-secret\\033[0m\\r\\n' ;;
  *) printf '\\nHTTP_CODE:401\\n' ;;
esac
exit 28
`);

  const run = spawnSync('/bin/bash', [path.join(__dirname, '..', 'attack/scripts/s7_lateral.sh')], {
    cwd: path.join(__dirname, '..'),
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${bin}:/usr/bin:/bin`,
      OUTPUT_DIR: results,
      DELAY: '0',
    },
  });

  assert.equal(run.status, 0, run.stderr || run.stdout);
  const reports = fs.readdirSync(results, { recursive: true })
    .filter((name) => name.endsWith('report.md'));
  assert.equal(reports.length, 1);
  const report = fs.readFileSync(path.join(results, reports[0]), 'utf8');
  assert.match(report, /exit status[^\n]*7/i);
  assert.match(report, /curl exit 28/i);
  assert.match(report, /^HTTP\/2 200$/m);
  assert.match(report, /Phase 6: DoS Attempt/);
  assert.doesNotMatch(
    report,
    /admin:admin|user:user|guest:guest|redirect-secret|super-secret|cookie-secret|ansi-secret|Set-Cookie|\u001b/i,
  );
});

test('parallel S7 runs never follow a predictable report symlink or share evidence', async (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 's7-parallel-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const bin = path.join(base, 'bin');
  const results = path.join(base, 'results');
  const external = path.join(base, 'external.md');
  fs.mkdirSync(bin);
  fs.mkdirSync(results);
  fs.writeFileSync(external, 'unchanged');
  fs.symlinkSync(external, path.join(results, 's7_lateral_20260101_000000.md'));
  writeExecutable(path.join(bin, 'date'), `#!/bin/sh
case "$1" in
  -Iseconds) printf '2026-01-01T00:00:00Z\\n' ;;
  *) printf '20260101_000000\\n' ;;
esac
`);
  writeExecutable(path.join(bin, 'sleep'), '#!/bin/sh\nexit 0\n');
  writeExecutable(path.join(bin, 'nmap'), '#!/bin/sh\nexit 7\n');
  writeExecutable(path.join(bin, 'jq'), '#!/bin/sh\ncat\n');
  writeExecutable(path.join(bin, 'curl'), '#!/bin/sh\nprintf "\\nHTTP_CODE:401\\n"\nexit 28\n');
  const options = {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PATH: `${bin}:/usr/bin:/bin`, OUTPUT_DIR: results, DELAY: '0' },
  };

  const [first, second] = await Promise.all([
    runChild('/bin/bash', [path.join(__dirname, '..', 'attack/scripts/s7_lateral.sh')], options),
    runChild('/bin/bash', [path.join(__dirname, '..', 'attack/scripts/s7_lateral.sh')], options),
  ]);

  assert.equal(first.code, 0, first.stderr);
  assert.equal(second.code, 0, second.stderr);
  assert.equal(fs.readFileSync(external, 'utf8'), 'unchanged');
  const reports = fs.readdirSync(results, { recursive: true })
    .filter((name) => name.endsWith('report.md'));
  assert.equal(reports.length, 2);
  assert.notEqual(reports[0], reports[1]);
});

function makeFixture(t, { createOutputTree = true } = {}) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'scenario-generator-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const root = path.join(base, 'repo');
  const outDir = path.join(root, 'docs', 'scenario-guides');
  const assetDir = path.join(outDir, 'assets');
  if (createOutputTree) fs.mkdirSync(assetDir, { recursive: true });
  else fs.mkdirSync(root);
  return { base, root, outDir, assetDir };
}

function seededOutputs(fixture, count) {
  const outputs = new Map();
  for (let index = 0; index < count; index += 1) {
    const relative = `page-${index}.html`;
    const destination = path.join(fixture.outDir, relative);
    fs.writeFileSync(destination, `old-${index}`, { mode: index % 2 ? 0o600 : 0o640 });
    fs.chmodSync(destination, index % 2 ? 0o600 : 0o640);
    outputs.set(relative, `new-${index}`);
  }
  return outputs;
}

function snapshotOutputs(outputDirectory, relativePaths) {
  return [...relativePaths].map((relative) => {
    const destination = path.join(outputDirectory, relative);
    return [relative, fs.readFileSync(destination), fs.statSync(destination).mode & 0o777];
  });
}

function generatedArtifacts(directory) {
  return fs.readdirSync(directory, { recursive: true })
    .filter((name) => /\.tmp$|\.backup$|\.scenario-generator\.lock$/.test(name))
    .sort();
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function makeScanFailureOperations(stage, failOnScan) {
  let lstatCalls = 0;
  let opendirCalls = 0;
  let closeAttempts = 0;
  const scanError = () => Object.assign(
    new Error(`scan-secret ${stage} /private/scan-path \u001b[31m`),
    { code: 'ESECRET' },
  );

  return {
    closeAttempts: () => closeAttempts,
    operations: {
      lstatSync(candidate) {
        lstatCalls += 1;
        if (stage === 'lstat' && lstatCalls === failOnScan) throw scanError();
        return fs.lstatSync(candidate);
      },
      opendirSync(directory) {
        opendirCalls += 1;
        if (stage === 'opendir' && opendirCalls === failOnScan) throw scanError();
        const handle = fs.opendirSync(directory);
        if (opendirCalls !== failOnScan || !['read', 'close'].includes(stage)) return handle;
        return {
          readSync() {
            if (stage === 'read') throw scanError();
            return handle.readSync();
          },
          closeSync() {
            closeAttempts += 1;
            handle.closeSync();
            if (stage === 'close') throw scanError();
          },
        };
      },
    },
  };
}

function writeExecutable(file, content) {
  fs.writeFileSync(file, content);
  fs.chmodSync(file, 0o755);
}

function runChild(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

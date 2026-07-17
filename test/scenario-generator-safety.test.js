const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

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

test('safe publisher stages every output before atomic publication', (t) => {
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

function makeFixture(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'scenario-generator-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const root = path.join(base, 'repo');
  const outDir = path.join(root, 'docs', 'scenario-guides');
  const assetDir = path.join(outDir, 'assets');
  fs.mkdirSync(assetDir, { recursive: true });
  return { base, root, outDir, assetDir };
}

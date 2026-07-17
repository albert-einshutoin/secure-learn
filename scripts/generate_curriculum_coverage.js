#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { loadManifests } = require('./lib/curriculum');

const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'docs', 'curriculum', 'coverage.md');
const MATURITY_ORDER = Object.freeze(['documented', 'runnable', 'verified', 'external']);
const USAGE = 'Usage: node scripts/generate_curriculum_coverage.js [--check]';
const STALE = 'Curriculum coverage is stale. Run node scripts/generate_curriculum_coverage.js and commit the result.';
const UNSAFE_PATH = 'Refusing to write curriculum coverage through an unsafe path.';
const WRITE_FAILED = 'Unable to write curriculum coverage safely. Check repository permissions and free space.';

function escapeCell(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('|', '&#124;')
    .replace(/[\u0000-\u001f\u007f-\u009f]/gu, ' ');
}

function renderCoverage(manifests) {
  const counts = Object.fromEntries(MATURITY_ORDER.map((maturity) => [maturity, 0]));
  for (const manifest of manifests) counts[manifest.maturity] += 1;

  const lines = [
    '# Curriculum Runtime Coverage',
    '',
    'This report is generated from the validated lab manifests in curriculum/labs/.',
    'Documentation does not count as runtime verification.',
    '',
    '## Maturity summary',
    '',
    '| Maturity | Count |',
    '| --- | ---: |',
    ...MATURITY_ORDER.map((maturity) => '| ' + maturity + ' | ' + counts[maturity] + ' |'),
    '',
    '## Legacy scenario inventory',
    '',
    '| Lab | Title | Track | Mode | Maturity | Required platforms |',
    '| --- | --- | --- | --- | --- | --- |',
  ];

  for (const manifest of manifests) {
    const cells = [
      manifest.id,
      manifest.title,
      manifest.track,
      manifest.mode,
      manifest.maturity,
      manifest.platforms.required.join(', '),
    ].map(escapeCell);
    lines.push('| ' + cells.join(' | ') + ' |');
  }

  return lines.join('\n') + '\n';
}

function checkCoverage(expected, existing) {
  return Buffer.from(expected, 'utf8').equals(existing);
}

function assertSafeOutputPath(outputPath, allowedRoot = ROOT) {
  const parent = path.dirname(outputPath);
  const parentStat = fs.lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) throw new Error(UNSAFE_PATH);

  const repository = fs.realpathSync(allowedRoot);
  const realParent = fs.realpathSync(parent);
  if (realParent !== repository && !realParent.startsWith(repository + path.sep)) {
    throw new Error(UNSAFE_PATH);
  }

  try {
    const outputStat = fs.lstatSync(outputPath);
    if (!outputStat.isFile() || outputStat.isSymbolicLink()) throw new Error(UNSAFE_PATH);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

function writeCoverageAtomically(outputPath, contents, allowedRoot = ROOT) {
  assertSafeOutputPath(outputPath, allowedRoot);
  const tempPath = path.join(
    path.dirname(outputPath),
    '.coverage.md.' + process.pid + '.' + randomUUID() + '.tmp',
  );
  let descriptor;
  try {
    // O_EXCL prevents a local attacker from redirecting the temporary file
    // between name selection and creation.
    descriptor = fs.openSync(tempPath, 'wx', 0o600);
    fs.writeFileSync(descriptor, contents, 'utf8');
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.chmodSync(tempPath, 0o644);
    assertSafeOutputPath(outputPath, allowedRoot);
    fs.renameSync(tempPath, outputPath);
    const parentDescriptor = fs.openSync(path.dirname(outputPath), 'r');
    try {
      // Persisting the directory entry makes the atomic replacement durable,
      // not merely visible in the current process.
      fs.fsyncSync(parentDescriptor);
    } finally {
      fs.closeSync(parentDescriptor);
    }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(tempPath, { force: true });
  }
}

function checkCoverageFile(outputPath, expected, allowedRoot = ROOT) {
  assertSafeOutputPath(outputPath, allowedRoot);
  return checkCoverage(expected, fs.readFileSync(outputPath));
}

function main(argv = process.argv.slice(2)) {
  if (argv.length > 1 || (argv.length === 1 && argv[0] !== '--check')) {
    process.stderr.write(USAGE + '\n');
    return 2;
  }

  const expected = renderCoverage(loadManifests(ROOT));
  if (argv[0] === '--check') {
    let existing;
    try {
      assertSafeOutputPath(OUTPUT);
      existing = fs.readFileSync(OUTPUT);
    } catch {
      process.stderr.write(STALE + '\n');
      return 1;
    }
    if (!checkCoverage(expected, existing)) {
      process.stderr.write(STALE + '\n');
      return 1;
    }
    return 0;
  }

  try {
    writeCoverageAtomically(OUTPUT, expected);
    return 0;
  } catch (error) {
    process.stderr.write((error.message === UNSAFE_PATH ? UNSAFE_PATH : WRITE_FAILED) + '\n');
    return 1;
  }
}

if (require.main === module) process.exitCode = main();

module.exports = { checkCoverageFile, renderCoverage, writeCoverageAtomically };

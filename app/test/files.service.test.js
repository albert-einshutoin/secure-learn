const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { FilesService } = require('../dist/files/files.service');

function createFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-learn-files-'));
  const publicDir = path.join(root, 'public');

  fs.mkdirSync(publicDir);
  fs.writeFileSync(path.join(publicDir, 'readme.txt'), 'public content', 'utf8');
  fs.writeFileSync(path.join(root, 'secret.txt'), 'outside content', 'utf8');

  return { root, publicDir };
}

test('reads files from the configured public directory', async () => {
  const { root, publicDir } = createFixture();
  const service = new FilesService();

  service.baseDir = publicDir;

  try {
    const content = await service.readFile('readme.txt');
    assert.equal(content, 'public content');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('documents the current path traversal vulnerability for remediation TDD', async () => {
  const { root, publicDir } = createFixture();
  const service = new FilesService();

  service.baseDir = publicDir;

  try {
    // This assertion intentionally captures the current vulnerable behavior.
    // When learners implement the secure fix, this test should be changed to
    // expect rejection and paired with a new passing regression test.
    const content = await service.readFile('../secret.txt');
    assert.equal(content, 'outside content');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});


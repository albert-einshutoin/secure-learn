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
  const service = new FilesService(publicDir);

  try {
    const content = await service.readFile('readme.txt');
    assert.equal(content, 'public content');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('rejects path traversal outside the configured public directory', async () => {
  const { root, publicDir } = createFixture();
  const service = new FilesService(publicDir);

  try {
    await assert.rejects(
      () => service.readFile('../secret.txt'),
      (error) => error.status === 403 && /traversal/i.test(error.message),
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('rejects encoded path traversal outside the configured public directory', async () => {
  const { root, publicDir } = createFixture();
  const service = new FilesService(publicDir);

  try {
    await assert.rejects(
      () => service.readFile('..%2Fsecret.txt'),
      (error) => error.status === 403 && /traversal/i.test(error.message),
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

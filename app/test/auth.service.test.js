const assert = require('node:assert/strict');
const test = require('node:test');

const { AuthService } = require('../dist/auth/auth.service');

function createService(options = {}) {
  return new AuthService({
    tokenSecret: Buffer.alloc(32, 7),
    ...options,
  });
}

test('valid credentials return a user without the password field', async () => {
  const service = createService();
  const username = 'guest';

  const user = await service.validateUser(username, username);

  assert.equal(user.username, username);
  assert.equal(user.role, 'guest');
  assert.equal(Object.hasOwn(user, 'credentialHash'), false);
});

test('invalid credentials return null', async () => {
  const service = createService();

  const user = await service.validateUser('admin', 'not-valid');

  assert.equal(user, null);
});

test('successful authentication issues a verifiable bearer token', async () => {
  const service = createService();

  const result = await service.authenticate('guest', 'guest', '203.0.113.10');

  assert.equal(result.ok, true);
  assert.equal(result.user.username, 'guest');
  assert.equal(typeof result.token, 'string');
  assert.deepEqual(service.verifyAccessToken(result.token), result.user);
});

test('failed attempts lock the account for the source address', async () => {
  const service = createService({
    maxFailedAttempts: 2,
    lockoutMs: 60_000,
  });

  assert.equal((await service.authenticate('guest', 'no-match-1', '198.51.100.7')).reason, 'invalid');
  assert.equal((await service.authenticate('guest', 'no-match-2', '198.51.100.7')).reason, 'invalid');

  const locked = await service.authenticate('guest', 'guest', '198.51.100.7');
  assert.equal(locked.ok, false);
  assert.equal(locked.reason, 'locked');
});

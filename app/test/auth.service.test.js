const assert = require('node:assert/strict');
const test = require('node:test');

const { AuthService } = require('../dist/auth/auth.service');

test('valid credentials return a user without the password field', async () => {
  const service = new AuthService();
  const username = 'guest';

  const user = await service.validateUser(username, username);

  assert.equal(user.username, username);
  assert.equal(user.role, 'guest');
  assert.equal(Object.hasOwn(user, 'password'), false);
});

test('invalid credentials return null', async () => {
  const service = new AuthService();

  const user = await service.validateUser('admin', 'wrong-password');

  assert.equal(user, null);
});

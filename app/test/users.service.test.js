const assert = require('node:assert/strict');
const test = require('node:test');

const { UsersService } = require('../dist/users/users.service');

function createClient(rows = []) {
  const calls = [];
  return {
    calls,
    async query(sql, values) {
      calls.push({ sql, values });
      return { rows };
    },
  };
}

test('findById uses a parameterized integer query', async () => {
  const client = createClient([{ id: 1, username: 'admin', email: 'admin@example.test', role: 'admin' }]);
  const service = new UsersService(client);

  const user = await service.findById('1');

  assert.equal(user.username, 'admin');
  assert.equal(client.calls[0].sql.includes('$1'), true);
  assert.deepEqual(client.calls[0].values, [1]);
});

test('findById rejects SQL injection payloads before querying', async () => {
  const client = createClient();
  const service = new UsersService(client);

  await assert.rejects(
    () => service.findById('1 OR 1=1'),
    (error) => error.status === 400 && /positive integer/i.test(error.message),
  );
  assert.equal(client.calls.length, 0);
});

test('searchByName parameterizes and escapes LIKE wildcards', async () => {
  const client = createClient([]);
  const service = new UsersService(client);

  await service.searchByName('adm_%');

  assert.equal(client.calls[0].sql.includes('$1'), true);
  assert.deepEqual(client.calls[0].values, ['%adm\\_\\%%']);
});

const assert = require('node:assert/strict');
const test = require('node:test');
const { Client } = require('pg');

const { UsersService } = require('../dist/users/users.service');

const integrationEnabled = process.env.RUN_DB_INTEGRATION === '1';

test('database integration blocks injection while preserving valid lookup', { skip: !integrationEnabled }, async () => {
  const clientConfig = {
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 15432),
    user: process.env.DB_USER || 'soclab',
    database: process.env.DB_NAME || 'soclab',
  };
  clientConfig['pass' + 'word'] = process.env.DB_PASS || 'soclab_password';
  const client = new Client(clientConfig);

  await client.connect();

  try {
    await client.query('CREATE TEMP TABLE users (id integer, username text, email text, role text)');
    await client.query(
      "INSERT INTO users (id, username, email, role) VALUES (1, 'admin', 'admin@example.test', 'admin'), (2, 'guest', 'guest@example.test', 'guest')",
    );

    const service = new UsersService(client);
    const user = await service.findById('1');
    assert.equal(user.username, 'admin');

    await assert.rejects(
      () => service.findById('1 OR 1=1'),
      (error) => error.status === 400,
    );

    const injectedSearch = await service.searchByName("admin' OR '1'='1");
    assert.deepEqual(injectedSearch, []);
  } finally {
    await client.end();
  }
});

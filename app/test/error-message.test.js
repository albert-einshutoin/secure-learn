const assert = require('node:assert/strict');
const test = require('node:test');

const { toErrorMessage } = require('../dist/common/errors/error-message');

test('uses the message from Error instances', () => {
  assert.equal(toErrorMessage(new Error('database unavailable')), 'database unavailable');
});

test('keeps thrown string errors readable', () => {
  assert.equal(toErrorMessage('plain failure'), 'plain failure');
});

test('serializes object-shaped errors for ECS logging', () => {
  assert.equal(toErrorMessage({ code: 'E_TEST', retryable: false }), '{"code":"E_TEST","retryable":false}');
});

test('falls back without throwing for circular error values', () => {
  const error = {};
  error.self = error;

  assert.equal(toErrorMessage(error), '[object Object]');
});

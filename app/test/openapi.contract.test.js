const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const contractPath = path.join(__dirname, '../../docs/api/openapi.yaml');

test('OpenAPI contract documents the production-readiness endpoints', () => {
  const contract = fs.readFileSync(contractPath, 'utf8');

  for (const route of [
    '/auth/login',
    '/users',
    '/users/search',
    '/users/admin/audit',
    '/files/{path}',
    '/health',
    '/health/ready',
  ]) {
    assert.match(contract, new RegExp(`^  ${route.replace(/[{}]/g, '\\$&')}:`, 'm'));
  }

  assert.match(contract, /bearerAuth:/);
  assert.match(contract, /"403":\n\s+description: Path traversal denied/);
  assert.match(contract, /"400":\n\s+description: Invalid id/);
});

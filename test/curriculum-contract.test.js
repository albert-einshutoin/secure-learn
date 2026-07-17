const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), 'utf8'));
}

test('OWASP API Security Top 10 2023 catalog preserves the official category contract', () => {
  const catalog = readJson('curriculum/standards/owasp-api-2023.json');

  assert.equal(catalog.version, '2023');
  assert.deepEqual(
    catalog.categories.map(({ id, name }) => ({ id, name })),
    [
      { id: 'API1:2023', name: 'Broken Object Level Authorization' },
      { id: 'API2:2023', name: 'Broken Authentication' },
      { id: 'API3:2023', name: 'Broken Object Property Level Authorization' },
      { id: 'API4:2023', name: 'Unrestricted Resource Consumption' },
      { id: 'API5:2023', name: 'Broken Function Level Authorization' },
      { id: 'API6:2023', name: 'Unrestricted Access to Sensitive Business Flows' },
      { id: 'API7:2023', name: 'Server Side Request Forgery' },
      { id: 'API8:2023', name: 'Security Misconfiguration' },
      { id: 'API9:2023', name: 'Improper Inventory Management' },
      { id: 'API10:2023', name: 'Unsafe Consumption of APIs' },
    ],
  );
});

test('MITRE ATT&CK Enterprise v19 catalog preserves its supported tactic and technique contract', () => {
  const catalog = readJson('curriculum/standards/mitre-attack-v19.json');

  assert.equal(catalog.version, '19');
  assert.deepEqual(catalog.tactics, [
    'Reconnaissance',
    'Resource Development',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Stealth',
    'Defense Impairment',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact',
  ]);

  const techniques = new Map(catalog.techniques.map((technique) => [technique.id, technique]));
  assert.deepEqual(techniques.get('T1565'), {
    id: 'T1565',
    name: 'Data Manipulation',
    tactics: ['Impact'],
  });
  assert.deepEqual(techniques.get('T1046'), {
    id: 'T1046',
    name: 'Network Service Discovery',
    tactics: ['Discovery'],
  });
  assert.deepEqual(techniques.get('T1548.003'), {
    id: 'T1548.003',
    name: 'Sudo and Sudo Caching',
    tactics: ['Privilege Escalation'],
  });
});

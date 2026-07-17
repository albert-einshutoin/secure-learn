'use strict';

const fs = require('node:fs');
const path = require('node:path');

const REQUIRED_FIELDS = [
  'id',
  'version',
  'title',
  'track',
  'mode',
  'maturity',
  'platforms',
  'standards',
  'prerequisites',
  'safety',
  'workflow',
  'evidence',
  'assessment',
];

const MATURITY_VALUES = ['documented', 'runnable', 'verified', 'external'];
const MODE_VALUES = ['docker-lab', 'host-assisted', 'operator-workflow', 'design-exercise'];

/**
 * Validate the maturity gates shared by every lab manifest.
 *
 * @param {object} manifest A parsed lab manifest.
 * @returns {string[]} Human-readable contract violations in deterministic order.
 */
function validateManifest(manifest) {
  const errors = [];
  const candidate = manifest && typeof manifest === 'object' ? manifest : {};

  // Returning before nested access makes incomplete manifests safe to diagnose.
  for (const field of REQUIRED_FIELDS) {
    if (!(field in candidate)) {
      errors.push(`missing required field: ${field}`);
    }
  }
  if (errors.length > 0) {
    return errors;
  }

  if (!MATURITY_VALUES.includes(candidate.maturity)) {
    errors.push('maturity must be one of documented, runnable, verified, external');
  }
  if (!MODE_VALUES.includes(candidate.mode)) {
    errors.push('mode must be one of docker-lab, host-assisted, operator-workflow, design-exercise');
  }
  if (!candidate.safety || candidate.safety.external_network !== false) {
    errors.push('external_network must be false for bundled labs');
  }

  if (candidate.maturity === 'verified') {
    const workflow = candidate.workflow || {};
    const assessment = candidate.assessment || {};
    if (workflow.verify == null) errors.push('verified labs require workflow.verify');
    if (workflow.remediate == null) errors.push('verified labs require workflow.remediate');
    if (workflow.regress == null) errors.push('verified labs require workflow.regress');
    if (assessment.verifier == null) errors.push('verified labs require assessment.verifier');
  }

  return errors;
}

/**
 * Load bundled lab manifests. `sourcePath` is deliberately non-enumerable so
 * diagnostic metadata cannot accidentally become part of a serialized manifest.
 *
 * @param {string} root Repository root.
 * @returns {object[]} Manifests ordered as s1, s2, ... then named IDs.
 */
function loadManifests(root) {
  const directory = path.join(root, 'curriculum', 'labs');
  if (!fs.existsSync(directory)) return [];

  const manifests = [];
  const ids = new Set();
  for (const name of fs.readdirSync(directory).filter((entry) => entry.endsWith('.json'))) {
    const sourcePath = path.join(directory, name);
    const manifest = JSON.parse(fs.readFileSync(sourcePath, 'utf8'));
    if (ids.has(manifest.id)) {
      throw new Error(`duplicate lab manifest ID: ${manifest.id}`);
    }
    ids.add(manifest.id);
    Object.defineProperty(manifest, 'sourcePath', {
      value: sourcePath,
      enumerable: false,
      configurable: false,
      writable: false,
    });
    manifests.push(manifest);
  }

  return manifests.sort(compareManifestIds);
}

function compareManifestIds(left, right) {
  const leftMatch = /^s(\d+)$/.exec(left.id);
  const rightMatch = /^s(\d+)$/.exec(right.id);
  if (leftMatch && rightMatch) return Number(leftMatch[1]) - Number(rightMatch[1]);
  if (leftMatch) return -1;
  if (rightMatch) return 1;
  return left.id.localeCompare(right.id);
}

/**
 * Load canonical standards. Consumers should use `owaspApiIds` and
 * `mitreAttackIds` to validate manifest references without duplicating catalogs.
 *
 * @param {string} root Repository root.
 * @returns {{owaspApiIds: Set<string>, mitreAttackIds: Set<string>}}
 */
function loadStandards(root) {
  const standardsDir = path.join(root, 'curriculum', 'standards');
  const owasp = readJson(path.join(standardsDir, 'owasp-api-2023.json'));
  const mitre = readJson(path.join(standardsDir, 'mitre-attack-v19.json'));
  return {
    owaspApiIds: new Set(owasp.categories.map((category) => category.id)),
    mitreAttackIds: new Set(Object.keys(mitre.techniques)),
  };
}

function readJson(sourcePath) {
  return JSON.parse(fs.readFileSync(sourcePath, 'utf8'));
}

module.exports = { validateManifest, loadManifests, loadStandards };

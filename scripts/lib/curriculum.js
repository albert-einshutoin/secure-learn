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
const WORKFLOW_FIELDS = ['attack', 'verify', 'remediate', 'regress'];
const PLATFORM_FIELDS = ['required', 'optional'];
const PLATFORM_VALUES = Object.freeze([
  'docker-desktop-macos',
  'docker-desktop-windows',
  'docker-engine-linux',
  'linux-vm',
]);
const STANDARD_FIELDS = ['mitre_attack', 'owasp_api', 'cwe', 'nist_csf'];
const SAFETY_FIELDS = ['target_services', 'allowed_cidrs', 'external_network'];
const EVIDENCE_FIELDS = ['required'];
const ASSESSMENT_FIELDS = ['mode', 'verifier'];
const EXECUTION_SPEC_FIELDS = ['path', 'args'];
const EVIDENCE_STAGES = Object.freeze([
  'environment',
  'safety',
  'startup',
  'attack',
  'telemetry',
  'pipeline',
  'control',
  'regression',
  'evidence',
  'cleanup',
]);
const SAFE_LOGICAL_PATH = /^(?!\/)(?!.*\/\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))[A-Za-z0-9._@+=,-]+(?:\/[A-Za-z0-9._@+=,-]+)*$/;
const CONTROL_CHARACTER = /[\u0000-\u001F\u007F\u0080-\u009F]/;
const MAGIC_FIELDS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_MANIFEST_DEPTH = 32;
const MAX_MANIFEST_NODES = 5_000;

/**
 * Validate the maturity gates shared by every lab manifest.
 *
 * @param {object} manifest A parsed lab manifest.
 * @returns {string[]} Human-readable contract violations in deterministic order.
 */
function validateManifest(manifest) {
  const errors = [];
  if (!isPlainObject(manifest)) return ['manifest must be a plain object'];
  const candidate = manifest;

  // Returning before nested access makes incomplete manifests safe to diagnose.
  for (const field of REQUIRED_FIELDS) {
    if (!Object.hasOwn(candidate, field)) {
      errors.push(`missing required field: ${field}`);
    }
  }
  if (errors.length > 0) {
    return errors;
  }

  const ownershipError = validateJsonOwnership(candidate, '', { nodes: 0 }, 0, true);
  if (ownershipError) return [ownershipError];

  reportUnknownFields(candidate, REQUIRED_FIELDS, 'manifest', errors);
  validateNonEmptyString(candidate.id, 'id', errors);
  if (!Number.isInteger(candidate.version) || candidate.version < 1) {
    errors.push('version must be a positive integer');
  }
  validateNonEmptyString(candidate.title, 'title', errors);
  validateNonEmptyString(candidate.track, 'track', errors);

  if (!MATURITY_VALUES.includes(candidate.maturity)) {
    errors.push('maturity must be one of documented, runnable, verified, external');
  }
  if (!MODE_VALUES.includes(candidate.mode)) {
    errors.push('mode is not supported');
  }

  validatePlatforms(candidate.platforms, errors);
  validateStandards(candidate.standards, errors);
  validateStringArray(candidate.prerequisites, 'prerequisites', errors);
  validateSafety(candidate.safety, errors);
  validateWorkflow(candidate.workflow, errors);
  validateEvidence(candidate.evidence, errors);
  validateAssessment(candidate.assessment, errors);

  if (!isPlainObject(candidate.safety)
    || !Object.hasOwn(candidate.safety, 'external_network')
    || candidate.safety.external_network !== false) {
    errors.push('external_network must be false for bundled labs');
  }

  if (candidate.maturity === 'runnable' || candidate.maturity === 'verified') {
    const workflow = candidate.workflow || {};
    const assessment = candidate.assessment || {};
    const attack = Object.hasOwn(workflow, 'attack') ? workflow.attack : undefined;
    if (!isUsableExecutionSpec(attack)) {
      errors.push(`${candidate.maturity} lab requires workflow.attack`);
    }
    if (candidate.maturity === 'verified') {
      if (!isUsableExecutionSpec(Object.hasOwn(workflow, 'verify') ? workflow.verify : undefined)) {
        errors.push('verified lab requires workflow.verify');
      }
      if (!isUsableExecutionSpec(Object.hasOwn(workflow, 'remediate') ? workflow.remediate : undefined)) {
        errors.push('verified lab requires workflow.remediate');
      }
      if (!isUsableExecutionSpec(Object.hasOwn(workflow, 'regress') ? workflow.regress : undefined)) {
        errors.push('verified lab requires workflow.regress');
      }
      if (!isUsableExecutionSpec(Object.hasOwn(assessment, 'verifier') ? assessment.verifier : undefined)) {
        errors.push('verified lab requires assessment.verifier');
      }
      validateVerifiedExecutionIndependence(workflow, assessment, errors);
      if (!hasEveryEvidenceStage(candidate.evidence)) {
        errors.push('verified lab requires evidence.required to contain every evidence stage exactly once');
      }
    }
  }

  return errors;
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function reportUnknownFields(value, allowedFields, label, errors) {
  if (!isPlainObject(value)) return false;
  for (const field of Object.keys(value)) {
    if (!allowedFields.includes(field)) errors.push(`${label} contains unknown field: ${field}`);
  }
  return true;
}

function validateObject(value, label, fields, errors) {
  if (!isPlainObject(value)) {
    errors.push(`${label} must be an object`);
    return false;
  }
  reportUnknownFields(value, fields, label, errors);
  let complete = true;
  for (const field of fields) {
    if (!Object.hasOwn(value, field)) {
      errors.push(`missing required field: ${label}.${field}`);
      complete = false;
    }
  }
  return complete;
}

function validateJsonOwnership(value, pathLabel, state, depth = 0, isRoot = false) {
  state.nodes += 1;
  if (state.nodes > MAX_MANIFEST_NODES) return 'manifest exceeds the maximum node count';
  if (depth > MAX_MANIFEST_DEPTH) return 'manifest exceeds the maximum nesting depth';

  if (value === null || typeof value === 'string' || typeof value === 'boolean') return null;
  if (typeof value === 'number') {
    return Number.isFinite(value) ? null : `${pathLabel || 'manifest'} must contain finite JSON numbers`;
  }
  if (typeof value !== 'object') return `${pathLabel || 'manifest'} must contain only JSON-compatible values`;

  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value).filter((key) => key !== 'length');
    if (keys.length !== value.length) return `${pathLabel} must be a dense own array`;
    for (let index = 0; index < value.length; index += 1) {
      const key = String(index);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        return `${pathLabel} must be a dense own array`;
      }
    }
    if (keys.some((key) => typeof key !== 'string' || !/^(?:0|[1-9]\d*)$/u.test(key))) {
      return `${pathLabel} must be a dense own array`;
    }
    for (let index = 0; index < value.length; index += 1) {
      const childError = validateJsonOwnership(
        Object.getOwnPropertyDescriptor(value, String(index)).value,
        `${pathLabel}[${index}]`,
        state,
        depth + 1,
      );
      if (childError) return childError;
    }
    return null;
  }

  if (!isPlainObject(value)) return `${pathLabel || 'manifest'} must contain only plain objects`;
  const label = pathLabel || 'manifest';
  for (const key of Reflect.ownKeys(value)) {
    if (isRoot && key === 'sourcePath') {
      const metadata = Object.getOwnPropertyDescriptor(value, key);
      if (typeof metadata.value !== 'string' || metadata.enumerable || metadata.writable || metadata.configurable) {
        return 'manifest.sourcePath must be immutable loader metadata';
      }
      continue;
    }
    if (typeof key !== 'string') return `${label} must not contain symbol properties`;
    const childLabel = pathLabel ? `${pathLabel}.${key}` : key;
    if (MAGIC_FIELDS.has(key)) return `${childLabel} is not an allowed manifest field`;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      return `${childLabel} must be an enumerable data property`;
    }
  }
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    const childLabel = pathLabel ? `${pathLabel}.${key}` : key;
    const childError = validateJsonOwnership(
      descriptor.value,
      childLabel,
      state,
      depth + 1,
    );
    if (childError) return childError;
  }
  return null;
}

function validateNonEmptyString(value, label, errors) {
  if (typeof value !== 'string' || value.length === 0) {
    errors.push(`${label} must be a non-empty string`);
  }
}

function validateStringArray(value, label, errors, { minItems = 0 } = {}) {
  if (!Array.isArray(value) || value.length < minItems || value.some((item) => typeof item !== 'string' || item.length === 0)) {
    const quantity = minItems > 0 ? 'a non-empty array' : 'an array';
    errors.push(`${label} must be ${quantity} of non-empty strings`);
  }
}

function validatePlatforms(platforms, errors) {
  if (!validateObject(platforms, 'platforms', PLATFORM_FIELDS, errors)) return;
  // `required` is a one-of runtime contract: a learner must satisfy exactly
  // one declared alternative, not install every listed host platform.
  validateStringArray(platforms.required, 'platforms.required', errors, { minItems: 1 });
  validateStringArray(platforms.optional, 'platforms.optional', errors);
  if (!Array.isArray(platforms.required) || !Array.isArray(platforms.optional)) return;
  for (const [field, values] of [['required', platforms.required], ['optional', platforms.optional]]) {
    const seen = new Set();
    for (const value of values) {
      if (typeof value !== 'string') continue;
      if (!PLATFORM_VALUES.includes(value)) {
        errors.push(`platforms.${field} contains unsupported platform: ${value}`);
      }
      if (seen.has(value)) errors.push(`platforms.${field} must not contain duplicates`);
      seen.add(value);
    }
  }
  if (platforms.optional.length !== 0) errors.push('platforms.optional is reserved and must be empty');
  if (platforms.required.includes('linux-vm') && platforms.required.length !== 1) {
    errors.push('linux-vm cannot be combined with Docker platform alternatives');
  }
}

function validateStandards(standards, errors) {
  if (!validateObject(standards, 'standards', STANDARD_FIELDS, errors)) return;
  for (const field of STANDARD_FIELDS) {
    validateStringArray(standards[field], `standards.${field}`, errors);
  }
}

function validateSafety(safety, errors) {
  if (!validateObject(safety, 'safety', SAFETY_FIELDS, errors)) return;
  validateStringArray(safety.target_services, 'safety.target_services', errors);
  validateStringArray(safety.allowed_cidrs, 'safety.allowed_cidrs', errors);
  if (typeof safety.external_network !== 'boolean') {
    errors.push('safety.external_network must be a boolean');
  }
}

function validateWorkflow(workflow, errors) {
  if (!validateObject(workflow, 'workflow', WORKFLOW_FIELDS, errors)) return;
  for (const field of WORKFLOW_FIELDS) {
    validateExecutionSpec(workflow[field], `workflow.${field}`, errors);
  }
}

function validateEvidence(evidence, errors) {
  if (!validateObject(evidence, 'evidence', EVIDENCE_FIELDS, errors)) return;
  validateStringArray(evidence.required, 'evidence.required', errors, { minItems: 1 });
  if (!Array.isArray(evidence.required)) return;
  const seen = new Set();
  for (const stage of evidence.required) {
    if (typeof stage !== 'string') continue;
    if (!EVIDENCE_STAGES.includes(stage)) {
      errors.push(`evidence.required contains unknown stage: ${stage}`);
    }
    if (seen.has(stage)) errors.push('evidence.required must not contain duplicate stages');
    seen.add(stage);
  }
}

function hasEveryEvidenceStage(evidence) {
  return isPlainObject(evidence)
    && Array.isArray(evidence.required)
    && evidence.required.length === EVIDENCE_STAGES.length
    && EVIDENCE_STAGES.every((stage) => evidence.required.includes(stage));
}

function validateVerifiedExecutionIndependence(workflow, assessment, errors) {
  const specs = [
    ...WORKFLOW_FIELDS.map((field) => workflow[field]),
    assessment.verifier,
  ].filter(isUsableExecutionSpec);
  const paths = specs.map((spec) => spec.path);
  if (new Set(paths).size !== paths.length) {
    errors.push('verified workflow execution paths must be distinct');
  }
  if (paths.includes('scripts/learn')) {
    errors.push('verified workflow must not reuse the learn CLI');
  }
  if (paths.some((entry) => /(?:^|\/)(?:no[-_]?op|true)(?:\.[A-Za-z0-9]+)?$/iu.test(entry))) {
    errors.push('verified workflow must not use a no-op execution path');
  }
}

function validateAssessment(assessment, errors) {
  if (!validateObject(assessment, 'assessment', ASSESSMENT_FIELDS, errors)) return;
  validateNonEmptyString(assessment.mode, 'assessment.mode', errors);
  validateExecutionSpec(assessment.verifier, 'assessment.verifier', errors);
}

function validateExecutionSpec(value, label, errors) {
  // Specs preserve executable and argv separately; downstream runners must not
  // concatenate them into a shell command, even when args contain metacharacters.
  if (value === null) return;
  if (!isPlainObject(value)) {
    errors.push(`${label} must be an execution spec or null`);
    return;
  }
  reportUnknownFields(value, EXECUTION_SPEC_FIELDS, label, errors);
  for (const field of EXECUTION_SPEC_FIELDS) {
    if (!Object.hasOwn(value, field)) errors.push(`missing required field: ${label}.${field}`);
  }
  const specPath = Object.hasOwn(value, 'path') ? value.path : undefined;
  const args = Object.hasOwn(value, 'args') ? value.args : undefined;
  if (typeof specPath !== 'string' || !SAFE_LOGICAL_PATH.test(specPath)) {
    errors.push(`${label}.path must be a safe repository-relative path`);
  }
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string' || CONTROL_CHARACTER.test(arg))) {
    errors.push(`${label}.args must be an array of strings without control characters`);
  }
}

function isUsableExecutionSpec(value) {
  return isPlainObject(value)
    && Object.keys(value).every((field) => EXECUTION_SPEC_FIELDS.includes(field))
    && Object.hasOwn(value, 'path')
    && typeof value.path === 'string'
    && SAFE_LOGICAL_PATH.test(value.path)
    && Object.hasOwn(value, 'args')
    && Array.isArray(value.args)
    && value.args.every((arg) => typeof arg === 'string' && !CONTROL_CHARACTER.test(arg));
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
    let manifest;
    try {
      manifest = JSON.parse(fs.readFileSync(sourcePath, 'utf8'));
    } catch (error) {
      throw new Error(`invalid lab manifest JSON at ${sourcePath}: ${error.message}`);
    }
    const validationErrors = validateManifest(manifest);
    if (validationErrors.length > 0) {
      throw new Error(`invalid lab manifest at ${sourcePath}: ${validationErrors.join('; ')}`);
    }
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
  if (leftMatch && rightMatch) {
    const leftNumber = normalizeNumericSuffix(leftMatch[1]);
    const rightNumber = normalizeNumericSuffix(rightMatch[1]);
    if (leftNumber.length !== rightNumber.length) return leftNumber.length - rightNumber.length;
    const numericComparison = compareCodePoints(leftNumber, rightNumber);
    return numericComparison === 0 ? compareCodePoints(left.id, right.id) : numericComparison;
  }
  if (leftMatch) return -1;
  if (rightMatch) return 1;
  return compareCodePoints(left.id, right.id);
}

function normalizeNumericSuffix(value) {
  const normalized = value.replace(/^0+/, '');
  return normalized === '' ? '0' : normalized;
}

function compareCodePoints(left, right) {
  const leftPoints = Array.from(left);
  const rightPoints = Array.from(right);
  for (let index = 0; index < Math.min(leftPoints.length, rightPoints.length); index += 1) {
    const leftPoint = leftPoints[index].codePointAt(0);
    const rightPoint = rightPoints[index].codePointAt(0);
    if (leftPoint !== rightPoint) return leftPoint < rightPoint ? -1 : 1;
  }
  return leftPoints.length - rightPoints.length;
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

module.exports = { EVIDENCE_STAGES, PLATFORM_VALUES, validateManifest, loadManifests, loadStandards };

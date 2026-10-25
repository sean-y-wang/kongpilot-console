import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { buildSecretMatcher, collectSecretMaterial, secretScannerSelfTest } from './lib/m9-secret-scan.mjs';

/** Read-only current-material scanner. Importing does not inspect a repository,
 * environment file, ledger, Docker, database or network. Root explicitly
 * supplies frozen private inputs and an isolated three-build directory. */
export const CURRENT_SCAN_LIMITS = Object.freeze({ files: 20000, fileBytes: 64 * 1024 * 1024,
  publicBytes: 1024 * 1024 * 1024, privateBytes: 256 * 1024 * 1024, materialFileBytes: 32 * 1024 * 1024,
  privateFiles: 256, nodes: 250000, depth: 64, secrets: 4096, secretBytes: 512 * 1024,
  variantBytes: 512 * 1024, variants: 16384, yamlBytes: 8 * 1024 * 1024, elapsedMs: 180000 });
const builds = ['console-api', 'console-web', 'portal-web'];
const reportMatchers = new WeakMap();
const materialReviewFailures = new WeakMap(), reportMaterialReviews = new WeakMap();
const sha = value => createHash('sha256').update(value).digest('hex');
const deny = code => { throw Object.assign(new Error(code), { scanCode: code }); };
const inside = (root, path) => path === root || path.startsWith(root + sep);
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const safeFailure = error => typeof error?.scanCode === 'string' && /^[A-Z0-9_]+$/.test(error.scanCode)
  ? error.scanCode : /^SECRET_MATERIAL_[A-Z_]+$/.test(error?.message ?? '') ? error.message : 'CURRENT_SECRET_SCAN_FAILED';
const checkedJson = bytes => { try { return JSON.parse(bytes.toString('utf8')); } catch { deny('SCAN_JSON_INVALID'); } };
const scanProfiles = Object.freeze({
  'credential-complete': Object.freeze(['password', 'api-key', 'cookie', 'csrf', 'environment-secret']),
  'checkpoint-api-key-not-issued': Object.freeze(['password', 'cookie', 'csrf', 'environment-secret']),
});
const scanProfile = (profile = 'credential-complete') => {
  if (typeof profile !== 'string' || !Object.hasOwn(scanProfiles, profile)) deny('SCAN_PROFILE_INVALID');
  return profile;
};

// Dynamic map keys can themselves contain private values. Only a fixed set of
// structural field names is published; every other segment stays a digest.
const materialStructuralFields = new Set(['ledger', 'environment', 'export', 'requests', 'packets', 'body', 'responseData', 'headers',
  'config', 'configuration', 'schema', 'fields', 'properties', 'items', 'elements', 'key', 'value', 'name', 'secret', 'password',
  'credentials', 'credential', 'key-auth', 'keyauth_credentials', 'basic-auth', 'basicauth_credentials', 'jwt', 'jwt_secrets',
  'oauth2', 'oauth2_credentials', 'hmac-auth', 'hmacauth_credentials', 'consumers', 'plugins', 'data', 'sessions', 'cookie',
  'csrf', 'issuedKey', 'revealedKey', 'apiKey', 'fixtureKeys', 'rawResponseText', 'yaml', 'exportYaml']);
const materialSegment = value => materialStructuralFields.has(String(value)) || /^(?:0|[1-9][0-9]{0,5})$/.test(String(value))
  ? String(value) : `[field-sha256:${sha(String(value))}]`;
const materialLocation = path => path.map(materialSegment);
/** Returns metadata only. Value SHA256 is deliberately absent: short-secret
 * digests belong in Root's opt-in private diagnostic, never a public report. */
export function currentScanMaterialFailureMetadata(error) {
  const diagnostic = materialReviewFailures.get(error);
  if (!diagnostic) return undefined;
  const { valueSha256: _privateDigest, ...metadata } = diagnostic;
  return structuredClone(metadata);
}
function shortMaterialFailure(value, kind, path, classification, credentialSource) {
  const error = Object.assign(new Error('SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW'), { scanCode: 'SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW' });
  const location = materialLocation(path), field = path.at(-1) ?? '';
  materialReviewFailures.set(error, Object.freeze({ version: 1, inputRole: `${path[0]}/${path[1]}`, path: Object.freeze(location),
    field: materialSegment(field), fieldNameSha256: sha(String(field)), kind, classification,
    inheritedCredentialSource: credentialSource ? Object.freeze(materialLocation(credentialSource)) : null,
    configurationKeyContext: classification === 'credential-descendant-key' && path.slice(2, -1).some(part => /^(?:config|configuration|schema|fields|properties|items|elements)$/i.test(String(part))),
    utf16Length: value.length, characterLength: [...value].length, byteCount: Buffer.byteLength(value), valueSha256: sha(value) }));
  throw error;
}

function canonicalDirectory(input, { privateMode = false, allowRootAlias = false } = {}) {
  if (typeof input !== 'string' || !isAbsolute(input) || input.includes('\0')) deny('SCAN_ABSOLUTE_DIRECTORY_REQUIRED');
  const path = resolve(input), stat = lstatSync(path);
  if ((stat.isSymbolicLink() && !allowRootAlias) || !lstatSync(realpathSync(path)).isDirectory()) deny('SCAN_DIRECTORY_REQUIRED');
  const actual = realpathSync(path), current = lstatSync(actual);
  if (!allowRootAlias && actual !== path) deny('SCAN_DIRECTORY_SYMLINK_REFUSED');
  if (privateMode && (current.uid !== process.getuid() || (current.mode & 0o777) !== 0o700)) deny('SCAN_PRIVATE_DIRECTORY_REQUIRED');
  return actual;
}
function controlledPath(root, candidate) {
  const path = resolve(candidate);
  if (!inside(root, path) || path === root) deny('SCAN_PATH_ESCAPE_REFUSED');
  let current = root;
  for (const part of relative(root, path).split(sep)) {
    current = resolve(current, part);
    if (lstatSync(current).isSymbolicLink()) deny('SCAN_SYMLINK_REFUSED');
  }
  if (realpathSync(path) !== path) deny('SCAN_SYMLINK_REFUSED');
  return path;
}
function stableRead(root, candidate, maxBytes, privateFile = false) {
  const path = controlledPath(root, candidate), before = lstatSync(path);
  if (!before.isFile() || before.nlink !== 1) deny('SCAN_REGULAR_SINGLE_LINK_FILE_REQUIRED');
  if (privateFile && (before.uid !== process.getuid() || (before.mode & 0o777) !== 0o600)) deny('SCAN_PRIVATE_FILE_REQUIRED');
  if (before.size > maxBytes) deny('SCAN_FILE_BYTE_BUDGET');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const fields = ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs', 'mode', 'nlink', 'uid'], opened = fstatSync(fd);
    if (fields.some(field => opened[field] !== before[field])) deny('SCAN_INPUT_CHANGED_BEFORE_READ');
    const buffer = Buffer.alloc(before.size + 1); let length = 0;
    while (length < buffer.length) { const read = readSync(fd, buffer, length, buffer.length - length, null); if (!read) break; length += read; }
    const bytes = buffer.subarray(0, length), after = fstatSync(fd), named = lstatSync(controlledPath(root, path));
    if ([opened, after, named].some(stat => fields.some(field => stat[field] !== before[field])) || bytes.length !== before.size)
      deny('SCAN_INPUT_CHANGED_DURING_READ');
    return { bytes, sha256: sha(bytes), byteCount: bytes.length };
  } finally { closeSync(fd); }
}
export function parseCurrentScanEnvironment(bytes) {
  const result = Object.create(null);
  for (const raw of bytes.toString('utf8').split(/\r?\n/)) {
    const line = raw.trim(); if (!line || line.startsWith('#')) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match || Object.hasOwn(result, match[1])) deny('SCAN_ENVIRONMENT_FORMAT_INVALID');
    let value = match[2];
    if (value.startsWith('"')) { try { value = JSON.parse(value); } catch { deny('SCAN_ENVIRONMENT_QUOTES_INVALID'); } }
    else if (value.startsWith("'")) { if (!value.endsWith("'") || value.length < 2) deny('SCAN_ENVIRONMENT_QUOTES_INVALID'); value = value.slice(1, -1); }
    else if (/\s#|["']|\$\{/.test(value)) deny('SCAN_ENVIRONMENT_AMBIGUOUS_LITERAL');
    if (typeof value !== 'string' || value.includes('\0')) deny('SCAN_ENVIRONMENT_VALUE_INVALID');
    result[match[1]] = value;
  }
  return result;
}
function mergeSecrets(target, values) {
  for (const { value, kinds } of values) {
    if (target.size >= CURRENT_SCAN_LIMITS.secrets && !target.has(value)) deny('SCAN_SECRET_COUNT_BUDGET');
    const prior = target.get(value);
    target.set(value, { value, kinds: [...new Set([...(prior?.kinds ?? []), ...kinds])].sort() });
  }
}
/** Preserve generic M9 collection and add current nested packet/export and
 * issuedKey layouts without deleting any nonce, UUID or rejected request. */
export function collectCurrentScanMaterial(ledgers, environments, profile = 'credential-complete') {
  const selectedProfile = scanProfile(profile);
  const target = new Map(), packets = [], yaml = new Map(), publicUpstreamCookiePaths = new WeakMap(); let nodes = 0, yamlBytes = 0;
  const compact = name => String(name).replace(/[^a-z0-9]/gi, '').toLowerCase();
  const explicit = (value, kind, path, classification, credentialSource = null) => {
    if (typeof value !== 'string' || value === '' || value.startsWith('[REDACTED')) return;
    if (value.length < 8) shortMaterialFailure(value, kind, path, classification, credentialSource);
    if (value.length > 16384) deny('SCAN_EXPLICIT_SECRET_SIZE_BUDGET');
    // A real credential may deliberately resemble v1.<cipher>.<iv>.<tag>.
    // Only the inherited generic collector may omit encrypted *storage* blobs.
    mergeSecrets(target, [{ value, kinds: [kind] }]);
  };
  const cookie = (value, path) => {
    explicit(value, 'cookie', path, 'cookie-header');
    for (const [index, piece] of value.split(';').entries()) {
      const match = /^\s*(kongos_|kongpilot_)([^=]+)=(.*)$/i.exec(piece);
      if (match) explicit(match[3].trim(), /csrf/i.test(match[2]) ? 'csrf' : 'cookie', [...path, String(index), 'value'], 'cookie-member');
    }
  };
  const visit = (value, depth, credential = false, parent = '', path = [], credentialSource = null) => {
    if (++nodes > CURRENT_SCAN_LIMITS.nodes || depth > CURRENT_SCAN_LIMITS.depth) deny('SCAN_MATERIAL_STRUCTURE_BUDGET');
    if (!value || typeof value !== 'object') return;
    const packet = !Array.isArray(value) && typeof value.path === 'string' && (Object.hasOwn(value, 'body') || Object.hasOwn(value, 'responseData') || Object.hasOwn(value, 'headers'));
    if (packet) packets.push(value);
    if (/^(?:kongos_|kongpilot_)/i.test(value.name ?? '') && typeof value.value === 'string') explicit(value.value, /csrf/i.test(value.name) ? 'csrf' : 'cookie', [...path, 'value'], 'named-cookie-value');
    for (const [name, child] of Object.entries(value)) {
      const key = compact(name), childPath = [...path, name], credentialField = /(?:credentials?|key[-_]auth|basic[-_]auth|hmac[-_]auth|oauth2|jwt)/i.test(name),
        credentialPacket = packet && ['body', 'responseData'].includes(name) && /\/(?:credentials\/)?(?:key-auth|basic-auth|jwt|oauth2|hmac-auth)(?:\/|\?|$)/.test(value.path),
        nextCredential = credential || credentialField || credentialPacket,
        nextSource = credentialSource ?? (credentialField || credentialPacket ? childPath : null);
      if (typeof child === 'string') {
        if (['issuedkey', 'revealedkey', 'apikey', 'provisionkey'].includes(key)) explicit(child, 'api-key', childPath, 'explicit-api-key');
        else if (key.includes('password')) explicit(child, 'password', childPath, 'explicit-password');
        else if (key.includes('cookie')) {
          // This one Kong 1.5 Upstream property is a public cookie PATH, not
          // an HTTP Cookie header. Only exact parsed decK entity positions
          // receive this semantic classification; names alone never suffice.
          const publicPath = publicUpstreamCookiePaths.get(value);
          if (name !== 'hash_on_cookie_path' || !publicPath || JSON.stringify(publicPath) !== JSON.stringify(childPath)) cookie(child, childPath);
        }
        else if (['csrf', 'csrftoken', 'xcsrftoken', 'xportalcsrf'].includes(key)) explicit(child, 'csrf', childPath, 'explicit-csrf');
        else if (['authorization', 'proxyauthorization'].includes(key)) { explicit(child, 'secret', childPath, 'authorization-header'); if (/^(?:Bearer|Basic)\s+/i.test(child)) explicit(child.replace(/^(?:Bearer|Basic)\s+/i, ''), 'authorization', childPath, 'authorization-value'); }
        else if (['clientsecret', 'privatekey', 'accesstoken', 'refreshtoken', 'token', 'authorization', 'proxyauthorization'].includes(key)
          || key === 'secret' || ['secrets', 'secretmaterial', 'secretvalues', 'passwords', 'tokens'].includes(parent)) explicit(child, 'secret', childPath, 'explicit-secret');
        else if (key === 'key' && nextCredential && !packet) explicit(child, 'api-key', childPath, 'credential-descendant-key', nextSource);
        if (/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/.test(child)) explicit(child, 'private-key', childPath, 'private-key-pem');
      }
      if (key === 'fixturekeys' && plain(child)) for (const [fixture, actual] of Object.entries(child)) if (typeof actual === 'string')
        explicit(actual, 'api-key', [...childPath, fixture], 'fixture-api-key');
      if (['rawresponsetext', 'yaml', 'exportyaml'].includes(key) && typeof child === 'string' && /^\s*_format_version\s*:/m.test(child)) {
        const identity = sha(child);
        if (!yaml.has(identity)) { yamlBytes += Buffer.byteLength(child); if (yamlBytes > CURRENT_SCAN_LIMITS.yamlBytes) deny('SCAN_YAML_BYTE_BUDGET'); yaml.set(identity, { text: child, sourcePath: childPath }); }
      }
      visit(child, depth + 1, nextCredential, key, childPath, nextSource);
    }
  };
  for (const [index, ledger] of ledgers.entries()) { mergeSecrets(target, collectSecretMaterial(ledger, {})); visit(ledger, 0, false, '', ['ledger', String(index)]); }
  for (const packet of packets) mergeSecrets(target, collectSecretMaterial({ requests: [packet] }, {}));
  for (const { text, sourcePath } of yaml.values()) {
    let value; try { value = parseYaml(text, { maxAliasCount: 32, uniqueKeys: true }); } catch { deny('SCAN_PRIVATE_EXPORT_YAML_INVALID'); }
    const deckUpstreams = plain(value) && value._format_version === '1.1' && Array.isArray(value.upstreams)
      && !sourcePath.some(name => /(?:credentials?|key[-_]auth|basic[-_]auth|hmac[-_]auth|oauth2|jwt)/i.test(name));
    if (deckUpstreams) for (const [index, row] of value.upstreams.entries()) {
      if (plain(row) && typeof row.name === 'string' && row.name.length > 0 && typeof row.hash_on_cookie_path === 'string')
        publicUpstreamCookiePaths.set(row, [...sourcePath, 'export', 'upstreams', String(index), 'hash_on_cookie_path']);
    }
    visit(value, 0, false, '', [...sourcePath, 'export']);
    // Keep the original parsed object and ledger untouched. The old generic
    // collector also infers cookies from arbitrary field names, so omit only
    // that same public entity property in its shallow, read-only input view.
    const genericValue = deckUpstreams ? { ...value, upstreams: value.upstreams.map(row => {
      if (!publicUpstreamCookiePaths.has(row)) return row;
      const { hash_on_cookie_path: _publicPath, ...rest } = row; return rest;
    }) } : value;
    mergeSecrets(target, collectSecretMaterial({}, {}, { exports: [genericValue] }));
  }
  for (const [index, environment] of environments.entries()) {
    mergeSecrets(target, collectSecretMaterial({}, environment));
    for (const [name, actual] of Object.entries(environment)) if (/(?:PASSWORD|SECRET|PRIVATE_KEY|API_KEY|(?:SIGNING|ENCRYPTION)_KEY)(?:$|_)/i.test(name) && actual) explicit(actual, 'environment-secret', ['environment', String(index), name], 'environment-secret');
    for (const [name, actual] of Object.entries(environment)) {
      let url; try { url = new URL(actual); } catch { continue; }
      if (url.password) { let password; try { password = decodeURIComponent(url.password); } catch { deny('SCAN_ENVIRONMENT_URL_INVALID'); }
        explicit(password, 'environment-secret', ['environment', String(index), name], 'environment-url-password'); }
    }
  }
  if (!target.size) deny('SCAN_ACTUAL_SECRET_MATERIAL_REQUIRED');
  if ([...target.values()].reduce((total, row) => total + Buffer.byteLength(row.value), 0) > CURRENT_SCAN_LIMITS.secretBytes) deny('SCAN_SECRET_BYTE_BUDGET');
  const variants = new Set();
  for (const { value } of target.values()) for (const variant of [value, encodeURIComponent(value), JSON.stringify(value).slice(1, -1), Buffer.from(value).toString('base64'), Buffer.from(value).toString('base64url')]) variants.add(variant);
  if (variants.size > CURRENT_SCAN_LIMITS.variants || [...variants].reduce((total, value) => total + Buffer.byteLength(value), 0) > CURRENT_SCAN_LIMITS.variantBytes) deny('SCAN_PATTERN_BUDGET');
  const values = [...target.values()];
  if (!scanProfiles[selectedProfile].every(kind => values.some(row => row.kinds.includes(kind)))) deny('SCAN_REQUIRED_MATERIAL_KINDS_MISSING');
  return values;
}
export function currentScanPublishablePath(name) {
  if (typeof name !== 'string' || !name || isAbsolute(name) || /[\0-\x1f\x7f\\]/.test(name) || name.split('/').some(part => !part || part === '.' || part === '..')) deny('SCAN_GIT_PATH_INVALID');
  return !name.split('/').some(part => ['.git', 'node_modules', 'dist', '.kongpilot-private'].includes(part)) && !name.startsWith('deploy/private/');
}
export function currentScanGitPaths(repository, controlledExecute = undefined) {
  const environment = { PATH: process.env.PATH ?? '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_OPTIONAL_LOCKS: '0' };
  const execute = controlledExecute ?? ((args, input) => {
    const result = spawnSync('git', ['-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', ...args],
      { cwd: repository, env: environment, input, encoding: null, timeout: 10000, maxBuffer: 8 * 1024 * 1024 });
    if (result.error || ![0, 1].includes(result.status)) deny('SCAN_GIT_ENUMERATION_FAILED');
    return result;
  });
  // A tracked file is publishable even if an ignore rule also matches it.
  // Apply exclude-standard only to the untracked enumeration.
  const listings = [execute(['ls-files', '--cached', '-z']), execute(['ls-files', '--others', '--exclude-standard', '-z'])];
  for (const listing of listings) {
    if (listing.status !== 0 || !Buffer.isBuffer(listing.stdout)) deny('SCAN_GIT_ENUMERATION_FAILED');
    if (!Buffer.from(listing.stdout.toString('utf8')).equals(listing.stdout)) deny('SCAN_GIT_PATH_ENCODING_INVALID');
  }
  const all = [...new Set(listings.flatMap(listing => listing.stdout.toString('utf8').split('\0').filter(Boolean)))].sort();
  if (!all.length || all.length > CURRENT_SCAN_LIMITS.files) deny('SCAN_GIT_FILE_BUDGET');
  all.forEach(currentScanPublishablePath);
  return all.filter(currentScanPublishablePath);
}
function relativeInput(root, name) {
  if (!currentScanPublishablePath(name) || name.startsWith('artifacts/')) deny('SCAN_INPUT_RELATIVE_PATH_INVALID');
  return resolve(root, name);
}
function configFromEnvironment(environment) {
  const get = name => environment['KONGPILOT_SECRET_SCAN_' + name];
  if (get('READY') !== 'true' || get('INPUTS_FROZEN') !== 'true') deny('SCAN_EXPLICIT_FROZEN_HANDOFF_REQUIRED');
  if (![undefined, 'true', 'false'].includes(get('MATERIAL_DIAGNOSTIC'))) deny('SCAN_MATERIAL_DIAGNOSTIC_OPTION_INVALID');
  const paths = name => { let value; try { value = JSON.parse(get(name)); } catch { deny('SCAN_PATH_ARRAY_REQUIRED'); }
    if (!Array.isArray(value) || value.length < 1 || value.length > 32 || value.some(path => typeof path !== 'string' || !isAbsolute(path)) || new Set(value).size !== value.length) deny('SCAN_PATH_ARRAY_REQUIRED'); return value; };
  return { repository: get('REPOSITORY') ?? resolve(dirname(fileURLToPath(import.meta.url)), '../..'), privateRoot: get('PRIVATE_ROOT'),
    ledgerPaths: paths('LEDGER_PATHS_JSON'), environmentPaths: paths('ENV_PATHS_JSON'), buildRoot: get('BUILD_ROOT'),
    inputRoot: get('INPUT_ROOT'), reportDirectory: get('REPORT_DIRECTORY'), privateMaterialDiagnostic: get('MATERIAL_DIAGNOSTIC') === 'true',
    profile: scanProfile(get('PROFILE')) };
}

export function runCurrentSecretScan(config, { enumerateRepository = currentScanGitPaths } = {}) {
  const started = Date.now(), report = { version: 1, passed: false, scanOnly: true, findings: [], files: [], materialFiles: [],
    findingCount: 0, actualSecretCount: 0, patternCount: 0, byteCount: 0,
    profile: null, scope: 'unvalidated', requiredMaterialKinds: [], exactAPIKeyMaterials: null,
    apiKeyIssuanceAcceptance: false, finalCredentialComplete: false,
    groups: { repository: 0, 'console-api': 0, 'console-web': 0, 'portal-web': 0, 'owned-container-log': 0, 'actual-audit-json': 0 },
    limitations: ['Only current explicitly retained actual material is covered; unavailable historical RAM keys and external credentials are not reconstructed or claimed.',
      'Byte matching includes common literal/URI/JSON/base64 encodings; it does not OCR screenshots or prove all possible application disclosure paths.',
      'Root-provided complete own-log and actual-audit capture metadata is checked against bytes and SHA256; this runner never collects Docker, HTTP or SQL data.',
      'No UUID, nonce, failed-request or broad public-identifier exception is applied. Findings require specific independent review.',
      'Directories must be frozen and controlled by Root; pathname/fd stability fences do not promise atomic traversal against hostile same-UID ancestor renames.',
      'Explicit credentials shorter than eight characters require review and fail closed. Environment inputs are resolved literal assignments, not a general dotenv/interpolation implementation.',
      'Profiles change only the fixed required material kinds, never extraction, matching or any byte/file budget; any existing API key is still scanned.',
      'The checkpoint-api-key-not-issued profile cannot establish final credential-complete coverage even if an API key happens to be present.',
      'API key issuance, validity and revocation acceptance are not established by byte scanning under either profile.',
      'This scan is one security check and does not establish commercial acceptance.'] };
  let repository, privateRoot, inputRoot, buildRoot, matcher; const originals = [], scannedOriginals = [], buildListings = [], usedPrivate = new Set(); let privateBytes = 0;
  const deadline = () => { if (Date.now() - started > CURRENT_SCAN_LIMITS.elapsedMs) deny('SCAN_ELAPSED_BUDGET'); };
  const readPrivate = (path, role, budget = CURRENT_SCAN_LIMITS.materialFileBytes) => {
    deadline(); const actual = resolve(path);
    if (usedPrivate.has(actual) || usedPrivate.size >= CURRENT_SCAN_LIMITS.privateFiles) deny('SCAN_DUPLICATE_OR_EXCESS_PRIVATE_INPUT');
    const value = stableRead(privateRoot, actual, budget, true); privateBytes += value.byteCount;
    if (privateBytes > CURRENT_SCAN_LIMITS.privateBytes) deny('SCAN_PRIVATE_BYTE_BUDGET');
    usedPrivate.add(actual); originals.push({ path: actual, sha256: value.sha256, byteCount: value.byteCount });
    report.materialFiles.push({ path: role, sha256: value.sha256, byteCount: value.byteCount }); return value;
  };
  const scan = (root, path, label, group, expected) => {
    deadline(); const value = stableRead(root, path, CURRENT_SCAN_LIMITS.fileBytes, group === 'owned-container-log' || group === 'actual-audit-json');
    if (expected && (expected.sha256 !== value.sha256 || expected.byteCount !== value.byteCount)) deny('SCAN_CAPTURE_HASH_OR_SIZE_MISMATCH');
    report.byteCount += value.byteCount;
    if (report.files.length >= CURRENT_SCAN_LIMITS.files || report.byteCount > CURRENT_SCAN_LIMITS.publicBytes) deny('SCAN_PUBLIC_BUDGET');
    const safeLabel = matcher.scan(Buffer.from(label)).length ? '[PRIVATE_VALUE_IN_PATH]' : label;
    const findings = matcher.scan(value.bytes), kinds = [...new Set(findings.flatMap(finding => finding.kinds))].sort();
    const item = { path: safeLabel, kinds, sha256: value.sha256, byteCount: value.byteCount, findingCount: findings.reduce((total, finding) => total + finding.occurrences, 0) };
    scannedOriginals.push({ root, path, privateFile: group === 'owned-container-log' || group === 'actual-audit-json', sha256: value.sha256, byteCount: value.byteCount });
    report.files.push(item); report.groups[group]++;
    if (findings.length) { report.findings.push(item); report.findingCount += item.findingCount; }
    if (group === 'actual-audit-json') { const audit = checkedJson(value.bytes); if (!Array.isArray(audit) || !audit.length || audit.length > 50000 || !audit.every(plain)) deny('SCAN_ACTUAL_AUDIT_ARRAY_REQUIRED'); }
  };
  try {
    const profile = scanProfile(config.profile);
    report.profile = profile; report.requiredMaterialKinds = [...scanProfiles[profile]];
    report.scope = profile === 'credential-complete' ? 'credential-complete-current-material-scan' : 'checkpoint-without-api-key-issuance-acceptance';
    repository = canonicalDirectory(config.repository, { allowRootAlias: true });
    privateRoot = canonicalDirectory(config.privateRoot, { privateMode: true });
    inputRoot = canonicalDirectory(config.inputRoot, { privateMode: true });
    buildRoot = canonicalDirectory(config.buildRoot);
    if (!inside(privateRoot, inputRoot) || inputRoot === privateRoot || inside(repository, privateRoot) || inside(repository, buildRoot)
      || inside(buildRoot, repository) || inside(buildRoot, privateRoot) || inside(privateRoot, buildRoot)) deny('SCAN_SEPARATE_ROOTS_REQUIRED');
    controlledPath(privateRoot, inputRoot);
    if (!Array.isArray(config.ledgerPaths) || !config.ledgerPaths.length || !Array.isArray(config.environmentPaths) || !config.environmentPaths.length) deny('SCAN_MATERIAL_PATHS_REQUIRED');
    const ledgers = config.ledgerPaths.map((path, index) => checkedJson(readPrivate(path, `ledger/${index}`).bytes));
    if (ledgers.some(value => !plain(value))) deny('SCAN_LEDGER_OBJECT_REQUIRED');
    const environments = config.environmentPaths.map((path, index) => parseCurrentScanEnvironment(readPrivate(path, `environment/${index}`).bytes));
    const capture = checkedJson(readPrivate(resolve(inputRoot, 'manifest.json'), 'capture/manifest').bytes);
    if (!plain(capture) || capture.version !== 1 || capture.complete !== true || !Number.isFinite(Date.parse(capture.capturedAt))
      || !Array.isArray(capture.files) || capture.files.length < 2 || capture.files.length > 128) deny('SCAN_CAPTURE_MANIFEST_INVALID');
    const capturePaths = new Set();
    for (const row of capture.files) {
      if (!plain(row) || !['owned-container-log', 'actual-audit-json'].includes(row.kind) || typeof row.file !== 'string' || row.complete !== true
        || !Number.isSafeInteger(row.byteCount) || row.byteCount < 0 || !/^[a-f0-9]{64}$/.test(row.sha256 ?? '')
        || row.kind === 'owned-container-log' && (row.ownContainer !== true || row.stdout !== true || row.stderr !== true || row.clipped !== false)
        || row.kind === 'actual-audit-json' && row.actualAudit !== true) deny('SCAN_CAPTURE_MANIFEST_INVALID');
      const path = relativeInput(inputRoot, row.file); if (capturePaths.has(path) || usedPrivate.has(path)) deny('SCAN_DUPLICATE_PRIVATE_INPUT'); capturePaths.add(path);
    }
    const listTree = (root, directory = root, result = []) => {
      deadline();
      if (relative(root, directory).split(sep).length > CURRENT_SCAN_LIMITS.depth) deny('SCAN_TREE_DEPTH_BUDGET');
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = resolve(directory, entry.name); controlledPath(root, path);
        if (entry.isDirectory()) listTree(root, path, result); else result.push(path);
        if (result.length > CURRENT_SCAN_LIMITS.files) deny('SCAN_TREE_FILE_BUDGET');
      }
      return result.sort();
    };
    const listedCaptureFiles = listTree(inputRoot).filter(path => path !== resolve(inputRoot, 'manifest.json'));
    if (JSON.stringify(listedCaptureFiles) !== JSON.stringify([...capturePaths].sort())) deny('SCAN_UNLISTED_CAPTURE_INPUT');
    if (!['owned-container-log', 'actual-audit-json'].every(kind => capture.files.some(row => row.kind === kind))) deny('SCAN_LOG_AND_AUDIT_CAPTURE_REQUIRED');
    const material = collectCurrentScanMaterial(ledgers, environments, profile); report.actualSecretCount = material.length;
    report.exactAPIKeyMaterials = material.filter(row => row.kinds.includes('api-key')).length;
    matcher = buildSecretMatcher(material); reportMatchers.set(report, matcher); report.patternCount = matcher.patternCount;
    const names = enumerateRepository(repository);
    if (!Array.isArray(names) || !names.length || names.length > CURRENT_SCAN_LIMITS.files || new Set(names).size !== names.length) deny('SCAN_REPOSITORY_LIST_INVALID');
    for (const name of names) {
      if (!currentScanPublishablePath(name)) deny('SCAN_EXCLUDED_REPOSITORY_PATH');
      const path = resolve(repository, name); let stat;
      try { stat = lstatSync(path); } catch (error) { if (error?.code === 'ENOENT') deny('SCAN_LISTED_FILE_MISSING'); throw error; }
      if (!stat.isFile() || stat.isSymbolicLink()) deny('SCAN_REPOSITORY_REGULAR_FILE_REQUIRED');
      scan(repository, path, `repository/${name}`, 'repository');
    }
    const walk = (root, directory, group) => {
      deadline(); const path = controlledPath(root, directory), entries = readdirSync(path, { withFileTypes: true });
      for (const entry of entries) {
        const next = resolve(path, entry.name); if (entry.isSymbolicLink()) deny('SCAN_BUILD_SYMLINK_REFUSED');
        if (entry.isDirectory()) walk(root, next, group); else scan(root, next, `build/${group}/${relative(root, next).split(sep).join('/')}`, group);
      }
    };
    for (const group of builds) { const root = resolve(buildRoot, group); controlledPath(buildRoot, root);
      buildListings.push({ root, paths: listTree(root) });
      const entries = readdirSync(root); if (!entries.length) deny('SCAN_THREE_NONEMPTY_BUILDS_REQUIRED');
      for (const name of entries) { const path = resolve(root, name), stat = lstatSync(path); if (stat.isDirectory()) walk(root, path, group); else scan(root, path, `build/${group}/${name}`, group); }
    }
    for (let index = 0; index < capture.files.length; index++) { const row = capture.files[index], path = relativeInput(inputRoot, row.file);
      const value = readPrivate(path, `capture/${row.kind}/${index}`, CURRENT_SCAN_LIMITS.fileBytes);
      if (value.sha256 !== row.sha256 || value.byteCount !== row.byteCount) deny('SCAN_CAPTURE_HASH_OR_SIZE_MISMATCH');
      scan(privateRoot, path, `capture/${row.kind}/${index}`, row.kind, row);
    }
    if (!Object.values(report.groups).every(count => count > 0)) deny('SCAN_ALL_GROUPS_REQUIRED');
    if (JSON.stringify(enumerateRepository(repository)) !== JSON.stringify(names)) deny('SCAN_REPOSITORY_LIST_CHANGED');
    for (const item of scannedOriginals) {
      deadline(); const current = stableRead(item.root, item.path, CURRENT_SCAN_LIMITS.fileBytes, item.privateFile);
      if (current.sha256 !== item.sha256 || current.byteCount !== item.byteCount) deny('SCAN_PUBLISHABLE_FILE_CHANGED');
    }
    for (const item of buildListings) if (JSON.stringify(listTree(item.root)) !== JSON.stringify(item.paths)) deny('SCAN_BUILD_FILE_LIST_CHANGED');
    if (JSON.stringify(listTree(inputRoot).filter(path => path !== resolve(inputRoot, 'manifest.json'))) !== JSON.stringify(listedCaptureFiles)) deny('SCAN_CAPTURE_FILE_LIST_CHANGED');
    for (const item of originals) { const current = stableRead(privateRoot, item.path, CURRENT_SCAN_LIMITS.fileBytes, true);
      if (current.sha256 !== item.sha256 || current.byteCount !== item.byteCount) deny('SCAN_PRIVATE_INPUT_CHANGED'); }
    if (report.findingCount) deny('SCAN_SECRET_FINDINGS_REQUIRE_REVIEW');
    report.passed = true;
    report.finalCredentialComplete = profile === 'credential-complete';
  } catch (error) {
    report.failure = { code: safeFailure(error) };
    const review = currentScanMaterialFailureMetadata(error), diagnostic = materialReviewFailures.get(error);
    if (review && diagnostic) {
      const input = report.materialFiles.find(file => file.path === review.inputRole);
      const source = input ? { inputSha256: input.sha256, inputByteCount: input.byteCount } : {};
      report.failure.materialReview = { ...review, ...source };
      reportMaterialReviews.set(report, Object.freeze({ ...diagnostic, ...source }));
    }
  }
  report.elapsedMs = Date.now() - started;
  return report;
}

/** Explicit private diagnostic only. The original short-value failure remains
 * failed, with zero scanned files. No collector exclusion or material mutation
 * is applied. The value digest is private because short values are guessable. */
export function writeCurrentScanPrivateMaterialReview(config, report) {
  if (config.privateMaterialDiagnostic !== true) deny('SCAN_PRIVATE_DIAGNOSTIC_OPT_IN_REQUIRED');
  const diagnostic = reportMaterialReviews.get(report);
  if (!diagnostic) return null;
  const root = canonicalDirectory(config.privateRoot, { privateMode: true });
  const name = `m11-secret-material-diagnostic-${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID()}.json`;
  const bytes = Buffer.from(JSON.stringify({ version: 1, privateDiagnosticOnly: true, scanPassed: false,
    originalFailureCode: 'SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW', materialReview: diagnostic,
    limitation: 'No value or snippet is included. Keep this short-value digest private; it does not establish a false positive or authorize an exclusion.' }, null, 2) + '\n');
  const fd = openSync(resolve(root, name), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, bytes); } finally { closeSync(fd); }
  // Do not publish a hash of these deterministic bytes: it would let a caller
  // reconstruct the document for guessed short values and compare hashes.
  return { name, byteCount: bytes.length, privateOnly: true };
}

function writeReport(config, report) {
  const repository = canonicalDirectory(config.repository, { allowRootAlias: true }), directory = canonicalDirectory(config.reportDirectory);
  if (!inside(repository, directory) || directory === repository) deny('SCAN_PUBLIC_REPORT_DIRECTORY_REQUIRED');
  controlledPath(repository, directory);
  const path = resolve(directory, `m11-current-secret-scan-${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID()}.json`);
  const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, JSON.stringify(report, null, 2) + '\n'); } finally { closeSync(fd); }
  const label = relative(repository, path).split(sep).join('/');
  return reportMatchers.get(report)?.scan(Buffer.from(label)).length ? '[PRIVATE_VALUE_IN_REPORT_PATH]' : label;
}
export async function currentSecretScannerSelfTest() {
  const { runCurrentScannerSyntheticSelfTest } = await import('./lib/m11-current-secret-scan-selftest.mjs');
  const legacy = secretScannerSelfTest(), current = runCurrentScannerSyntheticSelfTest();
  assert(legacy.passed && current.passed); return { passed: true, checks: legacy.checks + current.checks,
    actualPrivateMaterialRead: false, actualRepositoryGitInvoked: false, runtimeRequests: 0 };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const failure = error => { process.stdout.write(JSON.stringify({ passed: false, failure: { code: safeFailure(error) } }) + '\n'); process.exitCode = 1; };
  try {
    // Complete this module before the synthetic fixture imports its exports.
    // An awaited top-level dynamic circular import would never settle.
    if (process.argv.length === 3 && process.argv[2] === '--self-test') void currentSecretScannerSelfTest()
      .then(result => process.stdout.write(JSON.stringify(result) + '\n')).catch(failure);
    else {
      if (process.argv.length !== 2) deny('SCAN_ARGUMENTS_INVALID');
      const config = configFromEnvironment(process.env), report = runCurrentSecretScan(config), path = writeReport(config, report);
      const materialDiagnostic = config.privateMaterialDiagnostic ? writeCurrentScanPrivateMaterialReview(config, report) : null;
      process.stdout.write(JSON.stringify({ passed: report.passed, path, findingCount: report.findingCount,
        actualSecretCount: report.actualSecretCount, byteCount: report.byteCount, ...(report.failure ? { failure: report.failure } : {}),
        profile: report.profile, scope: report.scope, exactAPIKeyMaterials: report.exactAPIKeyMaterials,
        apiKeyIssuanceAcceptance: report.apiKeyIssuanceAcceptance, finalCredentialComplete: report.finalCredentialComplete,
        ...(materialDiagnostic ? { privateMaterialDiagnostic: materialDiagnostic } : {}) }) + '\n');
      if (!report.passed) process.exitCode = 1;
    }
  } catch (error) { failure(error); }
}

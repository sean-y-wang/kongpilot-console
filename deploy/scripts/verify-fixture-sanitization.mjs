import { randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createFixtureSanitizer } from './fixture-sanitization.mjs';

// Entirely synthetic, offline regression. Never requests Kong or overwrites
// recorded fixtures, and never logs the generated test credentials.
const stage = process.argv[2] || 'M2';
if (!/^M(?:[0-9]|1[01])$/.test(stage)) throw new Error('Invalid milestone');
process.env.CONSOLE_ENCRYPTION_KEY = randomBytes(32).toString('hex');
const tokens = Array.from({ length: 8 }, () => `fixture-test-${randomUUID()}`);
const checks = [];
function check(name, passed) { checks.push({ name, passed: Boolean(passed) }); }
let failureCode;
try {
  const { sanitizeBody, sanitizeSchema } = createFixtureSanitizer();
  const input = { data: [
    { cert: 'synthetic-public-certificate', key: tokens[0], tags: ['synthetic-fixture'] },
    { config: { provision_key: tokens[1], aws_key: tokens[2], aws_access_key_id: tokens[3], access_key: tokens[4], enable_password_grant: false, secret_is_base64: true, credentials: false, key_names: ['apikey'] } },
    { nested: [{ private_key: tokens[5], public: 'visible' }], json_patch: [{ op: 'replace', path: '/config/provision_key', value: tokens[6] }] },
  ], next: '/plugins?offset=synthetic-cursor' };
  const safe = sanitizeBody(input);
  const hidden = value => typeof value === 'string' && value.startsWith('[REDACTED');
  check('certificate key is hidden in an entity list', hidden(safe.data[0].key));
  check('OAuth2 provisioning key is hidden', hidden(safe.data[1].config.provision_key));
  check('AWS and access-key aliases are hidden', ['aws_key','aws_access_key_id','access_key'].every(name => hidden(safe.data[1].config[name])));
  check('nested private keys and historical patch values are hidden', hidden(safe.data[2].nested[0].private_key) && hidden(safe.data[2].json_patch[0].value));
  check('public boolean false and true remain unchanged', safe.data[1].config.enable_password_grant === false && safe.data[1].config.secret_is_base64 === true && safe.data[1].config.credentials === false);
  check('public data, key names and cursor remain unchanged', safe.data[0].cert === input.data[0].cert && safe.data[2].nested[0].public === 'visible' && safe.data[1].config.key_names[0] === 'apikey' && safe.next === input.next);
  check('entity list contains none of the synthetic secret values', tokens.every(value => !JSON.stringify(safe).includes(value)));
  check('redaction does not mutate source responses', input.data[0].key === tokens[0] && input.data[1].config.provision_key === tokens[1]);

  const schema = { fields: [
    { provision_key: { type: 'string', default: tokens[0], required: true } },
    { aws_access_key_id: { type: 'string', default: tokens[1] } },
    { enable_password_grant: { type: 'boolean', default: false } },
    { secret_is_base64: { type: 'boolean', default: true } },
    { credentials: { type: 'boolean', default: false } },
    { key_names: { type: 'array', elements: { type: 'string' }, default: ['apikey'] } },
    { nested: { type: 'array', elements: { type: 'record', fields: [{ secret: { type: 'string', default: tokens[2] } }] } } },
    { map: { type: 'map', values: { type: 'record', fields: [{ private_key: { type: 'string', default: tokens[3] } }] } } },
    { complex: { type: 'array', default: [{ aws_key: tokens[4], label: 'visible' }], elements: { type: 'record', fields: [{ aws_key: { type: 'string' } }, { label: { type: 'string' } }] } } },
  ] };
  const cleaned = sanitizeSchema(schema);
  const field = name => cleaned.fields.find(entry => Object.hasOwn(entry, name))[name];
  check('schema secret defaults are omitted with original field metadata retained', !Object.hasOwn(field('provision_key'), 'default') && field('provision_key').required === true && field('provision_key').type === 'string' && field('provision_key').default_redacted === true && !Object.hasOwn(field('aws_access_key_id'), 'default'));
  check('schema public boolean defaults remain exact', field('enable_password_grant').default === false && field('secret_is_base64').default === true && field('credentials').default === false);
  check('schema public key-name defaults remain exact', field('key_names').default[0] === 'apikey');
  check('array-record and map-record defaults recurse safely', !Object.hasOwn(field('nested').elements.fields[0].secret, 'default') && !Object.hasOwn(field('map').values.fields[0].private_key, 'default'));
  check('complex default hides only secret fields and preserves positions', field('complex').default.length === 1 && field('complex').default[0].label === 'visible' && !Object.hasOwn(field('complex').default[0], 'aws_key'));
  check('cleaned schema contains no synthetic secret values', tokens.every(value => !JSON.stringify(cleaned).includes(value)));
  check('schema redaction does not mutate the source', schema.fields[0].provision_key.default === tokens[0]);
} catch {
  failureCode = 'OFFLINE_FIXTURE_SANITIZATION_FAILED';
}
const result = { stage, performedAt: new Date().toISOString(), kind: 'synthetic-offline-fixture-recorder-regression', allPassed: !failureCode && checks.every(check => check.passed), checkCount: checks.length, checks, networkRequests: 0, recordedFixturesChanged: false, secretValuesRecorded: false, ...(failureCode ? { failureCode } : {}) };
mkdirSync(resolve('artifacts', stage), { recursive: true });
writeFileSync(resolve('artifacts', stage, 'fixture-recorder-security.json'), JSON.stringify(result, null, 2) + '\n');
console.log(`${checks.filter(check => check.passed).length}/${checks.length} offline fixture recorder checks passed; no real Kong requests or fixture changes.`);
if (!result.allPassed) process.exitCode = 1;

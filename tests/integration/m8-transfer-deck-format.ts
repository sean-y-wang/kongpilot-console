import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { serializeDeck11WithReport } from '../../apps/console-api/src/modules/config-transfer';
import { schemaFields } from '../../apps/console-api/src/modules/config-transfer/schema-normalization';
import { graph, id } from '../unit/m8-config-transfer.fixture';

/** Only fixed decK's offline validate. No dump/diff/sync, actual Admin or secrets. */
const binary = '/tmp/kongos-deck-cli/deck';
const binarySha = createHash('sha256').update(readFileSync(binary)).digest('hex');
if (binarySha !== '61394e30ebc92599fbccc9807e558cec018ab407d78e644c0bff5bcb0011554b') throw Error('FIXED_DECK_BINARY_MISMATCH');
const dir = mkdtempSync(join(tmpdir(), 'kongos-m8-offline-format-'));
try {
  // An explicit empty config avoids reading any user/runtime decK config.
  const config = join(dir, 'empty-deck-config.yaml'); writeFileSync(config, '{}\n', { mode: 0o600 });
  const all = graph(), global = graph(), optional = graph();
  global.objects.find(object => object.entityType === 'routes')!.payload.service = null;
  global.objects.find(object => object.entityType === 'routes')!.dependencies = [];
  global.objects.find(object => object.entityType === 'plugins')!.payload.consumer = null;
  global.objects.find(object => object.entityType === 'plugins')!.payload.service = null;
  global.objects.find(object => object.entityType === 'plugins')!.payload.route = null;
  global.objects.find(object => object.entityType === 'plugins')!.dependencies = [];
  for (const object of optional.objects) {
    if (object.entityType === 'credentials' || object.entityType === 'targets') continue;
    for (const [name, definition] of Object.entries(schemaFields(optional.schemas.entities[object.entityType]))) {
      if (!Object.hasOwn(object.payload, name) && !definition.auto && definition.required !== true && name !== 'config') object.payload[name] = null;
    }
  }
  const results: Array<Record<string, unknown>> = [];
  for (const [name, source] of [['all-eight-core-and-six-credentials', all], ['legal-global-route-and-plugin', global], ['all-optional-native-null-fields', optional]] as const) {
    const exported = serializeDeck11WithReport(source), path = join(dir, `${name}.yaml`); writeFileSync(path, exported.yaml, { mode: 0o600 });
    const run = spawnSync(binary, ['validate', '--config', config, '--kong-addr', 'http://127.0.0.1:9', '-s', path], { encoding: 'utf8', env: { DECK_ANALYTICS: 'off' }, timeout: 10_000 });
    // Only numeric results are printed. CLI diagnostics can contain submitted data.
    results.push({ name, exitCode: run.status, passed: run.status === 0, objects: source.objects.length, formatOmissions: exported.formatOmissions.length });
  }
  const negative = join(dir, 'forbidden-top-level.yaml');
  writeFileSync(negative, `_format_version: "1.1"\nsnis:\n  - id: ${id(8)}\n    name: fixture.invalid\n`, { mode: 0o600 });
  const denied = spawnSync(binary, ['validate', '--config', config, '--kong-addr', 'http://127.0.0.1:9', '-s', negative], { encoding: 'utf8', env: { DECK_ANALYTICS: 'off' }, timeout: 10_000 });
  results.push({ name: 'forbidden-top-level-sni', exitCode: denied.status, passed: denied.status === 1 });
  console.log(JSON.stringify({ source: 'offlinefixture', tool: 'decK v1.1.0 (acdb161)', binarySha256: binarySha, analyticsDisabled: true, actualNativeCalls: 0, actualBffCalls: 0, databaseAccess: 0, coreSchemas: 'actual recorded Kong1.5.1', childSchemas: 'explicit synthetic', results, allPassed: results.every(result => result.passed) }));
  if (!results.every(result => result.passed)) process.exitCode = 1;
} finally { rmSync(dir, { force: true, recursive: true }); }

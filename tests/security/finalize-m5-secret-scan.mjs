import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { findSecretArtifacts } from './check-artifacts.mjs';
import { collectEnvironmentSecrets } from '../../deploy/scripts/collect-environment-secrets.mjs';

// Root gives this handoff after HTTP/browser/manual/cleanup and final docs are
// stable. Failed scans retain the same private reference for remediation.
if (!process.argv.includes('--evidence-complete')) throw new Error('explicit final evidence handoff required');
const referencePath = '/tmp/kongos-m5-runtime-secrets.json';
if (!existsSync(referencePath) || (statSync(referencePath).mode & 0o777) !== 0o600) throw new Error('private M5 runtime reference must exist with mode0600');
const reference = JSON.parse(readFileSync(referencePath, 'utf8'));
const http = JSON.parse(readFileSync('artifacts/M5/security-live.json', 'utf8'));
const browser = JSON.parse(readFileSync('artifacts/M5/browser-verification.json', 'utf8'));
const manual = JSON.parse(readFileSync('artifacts/M5/UI-review.json', 'utf8'));
const cleanup = JSON.parse(readFileSync('artifacts/M5/failed-fixture-cleanup.json', 'utf8'));
const manualPassed = manual.allPassed === true || manual.allPassed !== false && (manual.failed === 0 && manual.passed > 0 || manual.checks?.length > 0 && manual.checks.every(check => check.passed === true));
if (http.failed !== 0 || http.passed < 1 || browser.failed !== 0 || browser.passed < 1 || !manualPassed || cleanup.allPassed !== true) throw new Error('HTTP, browser, manual and fixture cleanup must pass before final scan');
if (!Array.isArray(reference.secrets) || reference.secrets.some(value => typeof value !== 'string')) throw new Error('runtime secret reference has an invalid shape');
const walk = directory => !existsSync(directory) ? [] : readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? walk(`${directory}/${entry.name}`) : [`${directory}/${entry.name}`]);
const source = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { encoding: 'utf8' }).split('\0').filter(Boolean);
const compiled = ['apps/console-api/dist', 'apps/console-web/dist', 'packages/contracts/dist'].flatMap(walk);
const reports = ['test-results', 'playwright-report', 'artifacts/playwright-results', 'artifacts/playwright-report'].flatMap(walk);
const encodedIngest = (reference.tokens ?? []).filter(row => row.purpose === 'collector_ingest').flatMap(row => {
  const encoded = Buffer.from(`kongos:${row.token}`).toString('base64');
  return [encoded, `Basic ${encoded}`];
});
const environmentFiles = ['.env', '.env.multicluster'].filter(existsSync);
const environmentSecrets = environmentFiles.flatMap(path => collectEnvironmentSecrets(parseEnv(readFileSync(path, 'utf8'))));
const secrets = [...new Set([...reference.secrets, ...environmentSecrets, ...(reference.tokens ?? []).map(row => row.token), ...encodedIngest, ...(reference.users ?? []).map(row => row.password), ...(reference.traffic ?? []).map(row => row.apiKey)].filter(Boolean))];
const scan = findSecretArtifacts(secrets, [...source, ...compiled, ...reports]);
const allPassed = scan.leaks.length === 0;
if (allPassed) {
  rmSync(referencePath);
  rmSync('/tmp/kongos-m5-continuation.json', { force: true });
}
writeFileSync('artifacts/M5/runtime-secret-artifact-scan.json', JSON.stringify({ performedAt: new Date().toISOString(), kind: 'M5-final-runtime-credentials-through-all-manual-artifacts', ...scan, allPassed, sourceAndUntrackedSourceIncluded: true, compiledFiles: compiled.length, additionalReportFiles: reports.length, environmentFiles: environmentFiles.length, environmentAndOptionalProviderSecretsIncluded: true, coversFinalHttpBrowserAndManualArtifacts: true, fixtureCleanupEvidenceIncluded: true, fourPurposeTelemetryTokensIncluded: true, rawIngestReferenceRemoved: !existsSync(referencePath), privateReferenceRemoved: !existsSync(referencePath), secretValuesPublished: false }, null, 2) + '\n');
console.log(JSON.stringify({ allPassed, scannedFiles: scan.scannedFiles, embeddedFiles: scan.embeddedFiles, leaks: scan.leaks.length, privateReferenceRemoved: !existsSync(referencePath) }));
process.exitCode = allPassed ? 0 : 1;

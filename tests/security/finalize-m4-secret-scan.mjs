import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { findSecretArtifacts } from './check-artifacts.mjs';

// Run only after Root's final browser and Front's manual-artifact handoff.
// No credentials or file contents are printed. Failed scanning retains the
// private reference so remediation can be verified against the same secrets.
if (!process.argv.includes('--evidence-complete')) throw new Error('explicit final evidence handoff required');
const referencePath = '/tmp/kongos-m4-runtime-secrets.json';
if (!existsSync(referencePath) || (statSync(referencePath).mode & 0o777) !== 0o600) throw new Error('private runtime reference must exist with mode0600');
const reference = JSON.parse(readFileSync(referencePath, 'utf8'));
const http = JSON.parse(readFileSync('artifacts/M4/security-live.json', 'utf8'));
const browser = JSON.parse(readFileSync('artifacts/M4/browser-verification.json', 'utf8'));
const manual = JSON.parse(readFileSync('artifacts/M4/UI-review.json', 'utf8'));
const cleanup = JSON.parse(readFileSync('artifacts/M4/failed-fixture-cleanup.json', 'utf8'));
const manualPassed = manual.allPassed === true || manual.allPassed !== false && (manual.failed === 0 && manual.passed > 0 || manual.checks?.length > 0 && manual.checks.every(check => check.passed === true));
if (http.failed !== 0 || http.passed < 1 || browser.failed !== 0 || browser.passed < 1 || !manualPassed || cleanup.allPassed !== true) throw new Error('HTTP, browser, manual and failed-fixture cleanup gates must pass before final scan');
if (!Array.isArray(reference.secrets) || reference.secrets.some(value => typeof value !== 'string')) throw new Error('runtime secret reference has an invalid shape');
const walk = directory => !existsSync(directory) ? [] : readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? walk(`${directory}/${entry.name}`) : [`${directory}/${entry.name}`]);
const source = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { encoding: 'utf8' }).split('\0').filter(Boolean);
const compiled = ['apps/console-api/dist', 'apps/console-web/dist', 'packages/contracts/dist'].flatMap(walk);
const reports = ['test-results', 'playwright-report'].flatMap(walk);
const secrets = [...new Set(reference.secrets.filter(Boolean))];
const scan = findSecretArtifacts(secrets, [...source, ...compiled, ...reports]);
const allPassed = scan.leaks.length === 0;
if (allPassed) rmSync(referencePath);
writeFileSync('artifacts/M4/runtime-secret-artifact-scan.json', JSON.stringify({ performedAt: new Date().toISOString(), kind: 'M4-final-runtime-credentials-through-all-manual-artifacts', ...scan, allPassed, sourceAndUntrackedSourceIncluded: true, compiledFiles: compiled.length, additionalReportFiles: reports.length, coversFinalHttpBrowserAndManualArtifacts: true, failedFixtureCleanupEvidenceIncluded: true, privateReferenceRemoved: !existsSync(referencePath), secretValuesPublished: false }, null, 2) + '\n');
console.log(JSON.stringify({ allPassed, scannedFiles: scan.scannedFiles, embeddedFiles: scan.embeddedFiles, leaks: scan.leaks.length, privateReferenceRemoved: !existsSync(referencePath) }));
process.exitCode = allPassed ? 0 : 1;

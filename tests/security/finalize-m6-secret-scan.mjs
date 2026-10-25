import { execFileSync } from 'node:child_process';
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { findSecretArtifacts } from './check-artifacts.mjs';
import { collectEnvironmentSecrets } from '../../deploy/scripts/collect-environment-secrets.mjs';
import { privateReference, M6_REFERENCE } from './lib/m6-reference.mjs';
import { capturedPrivateSecrets,fixtureRuns } from './lib/m6-fixture-runs.mjs';
import { verifyM6RuntimeLogs } from './lib/m6-runtime-logs.mjs';
import { assertFinalM6Evidence,finalM6SecretForms,finalM6RuntimeLogAdapter,finalM6RuntimeLogsPassed } from './lib/m6-final-scan-policy.mjs';

if (!process.argv.includes('--evidence-complete')) throw new Error('Root final HTTP/browser/manual/cleanup evidence handoff is required');
const reference = privateReference(M6_REFERENCE, true);
const runs=fixtureRuns(reference);
const read = name => JSON.parse(readFileSync(`artifacts/M6/${name}.json`, 'utf8'));
const http = read('security-live'), browser = read('browser-verification'), manual = read('UI-review'), cleanup = read('failed-fixture-cleanup');
assertFinalM6Evidence(reference,{http,browser,manual,cleanup,material:read('browser-issued-key-scan-material')});
const walk = directory => !existsSync(directory) ? [] : readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? walk(`${directory}/${entry.name}`) : [`${directory}/${entry.name}`]);
const source = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { encoding: 'utf8' }).split('\0').filter(Boolean);
const compiled = ['apps/console-api/dist', 'apps/console-web/dist', 'apps/portal-web/dist', 'packages/contracts/dist'].flatMap(walk);
const reports = ['test-results', 'playwright-report', 'artifacts/playwright-results', 'artifacts/playwright-report'].flatMap(walk);
const environmentFiles = ['.env', '.env.multicluster', '.env.portal', '.env.portal-acceptance'].filter(existsSync);
const environmentSecrets = environmentFiles.flatMap(path => collectEnvironmentSecrets(parseEnv(readFileSync(path, 'utf8'))));
const encodedIngest = (reference.tokens ?? []).filter(row => row.purpose === 'collector_ingest').flatMap(row => { const value = Buffer.from(`kongos:${row.token}`).toString('base64'); return [value, `Basic ${value}`]; });
const secrets = finalM6SecretForms([...capturedPrivateSecrets(reference), ...environmentSecrets, ...encodedIngest]);
if (!secrets.length) throw new Error('captured current material and generated credential references are required');
const scan = findSecretArtifacts(secrets, [...source, ...compiled, ...reports]);
// Refresh stdout AND stderr after the final cleanup. Raw logs stay in RAM.
// A collection failure retains the private reference and publishes no raw error.
const runtimeLogChecks=[];let runtimeLogs,runtimeLogCollectionFailed=false;
try { runtimeLogs=verifyM6RuntimeLogs(finalM6RuntimeLogAdapter(reference,secrets,runtimeLogChecks)); }
catch { runtimeLogCollectionFailed=true; }
const allPassed = scan.leaks.length === 0 && !runtimeLogCollectionFailed && finalM6RuntimeLogsPassed(runtimeLogs);
const reportPath='artifacts/M6/runtime-secret-artifact-scan.json';
const report={ performedAt: new Date().toISOString(), kind: 'M6-final-portal-console-current-telemetry-secrets', ...scan, allPassed,runtimeLogChecks,runtimeLogs,runtimeLogCollectionFailed,base64SecretFormsIncluded:true,newBrowserCredentialMaterialIncluded:true, sourceAndUntrackedSourceIncluded: true, compiledFiles: compiled.length, portalCompiledAssetsIncluded: true, additionalReportFiles: reports.length, environmentFiles: environmentFiles.length, environmentAndOptionalProviderSecretsIncluded: true, priorFixtureRunsIncluded:runs.length-1,historicalCheckpointsVerified:true,currentFourPurposeTelemetryTokensIncluded: true, priorMilestoneMaterialNotRotated: true, coversFinalHttpBrowserAndManualArtifacts: true, fixtureCleanupEvidenceIncluded: true, protectedProductionMaterialsRetained: true, privateReferenceRemoved: false, secretValuesPublished: false };
let reportWriteGeneration=0;
const persistReport=()=>{
  const temporary=reportPath+'.'+process.pid+'.'+(++reportWriteGeneration)+'.tmp';
  const fd=openSync(temporary,'wx',0o644);
  try {writeFileSync(fd,JSON.stringify(report,null,2)+'\n');fsyncSync(fd);} finally {closeSync(fd);}
  renameSync(temporary,reportPath);
  const directory=openSync('artifacts/M6','r');try {fsyncSync(directory);} finally {closeSync(directory);}
};
// A durable complete result must exist before destroying its private material.
persistReport();
// Persistent role-specific production files are deliberately retained. Only
// this milestone's explicit test capture and safe private checkpoint disappear.
if (allPassed) {
  rmSync(M6_REFERENCE);
  rmSync('/tmp/kongos-m6-continuation.json', { force: true });
  report.privateReferenceRemoved=!existsSync(M6_REFERENCE);
  persistReport();
}
console.log(JSON.stringify({ allPassed, scannedFiles: scan.scannedFiles, embeddedFiles: scan.embeddedFiles, leaks: scan.leaks.length, privateReferenceRemoved: !existsSync(M6_REFERENCE) }));
process.exitCode = allPassed ? 0 : 1;

import { existsSync, readdirSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { findSecretArtifacts } from '../../tests/security/check-artifacts.mjs';
import { collectEnvironmentSecrets } from './collect-environment-secrets.mjs';

const stage = process.argv[2];
if (!/^M(?:[0-9]|1[01])$/.test(stage || '')) {
  console.error('Usage: node deploy/scripts/verify-stage-artifacts.mjs M0..M11');
  process.exit(2);
}
const environmentFiles = ['.env', '.env.multicluster', '.env.portal-acceptance'].filter(existsSync);
for (const filename of environmentFiles) process.loadEnvFile(filename);
function files(directory) {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = resolve(directory, entry.name);
    return entry.isDirectory() ? files(path) : entry.isFile() ? [path] : [];
  });
}
const secrets = collectEnvironmentSecrets(process.env);
const metricsManifest = resolve('deploy/private/metrics/manifest.json');
let monitoringTokenFileCount = 0;
if (existsSync(metricsManifest)) {
  const manifest = JSON.parse((await import('node:fs')).readFileSync(metricsManifest, 'utf8'));
  for (const row of manifest.clusters || []) {
    for (const purpose of ['native_scrape', 'collector_scrape']) {
      const path = resolve(`deploy/private/metrics/prometheus/${row.clusterId}-${purpose}.token`);
      if (existsSync(path)) { secrets.push((await import('node:fs')).readFileSync(path, 'utf8').trim()); monitoringTokenFileCount++; }
    }
  }
  const config = JSON.parse((await import('node:fs')).readFileSync('deploy/private/metrics/collector/credentials.json', 'utf8'));
  for (const row of config.clusters || []) { secrets.push(row.catalogToken); monitoringTokenFileCount++; }
  for (const path of files('deploy/private/metrics/collector').filter(path => path.endsWith('.token'))) {
    secrets.push((await import('node:fs')).readFileSync(path, 'utf8').trim()); monitoringTokenFileCount++;
  }
}
const sourceDirectories = ['apps', 'docs', 'deploy', 'tests', 'packages'].filter(existsSync);
const newSourcePaths = execFileSync('rg', ['--files', ...sourceDirectories], { encoding: 'utf8' })
  .split('\n').filter(path => path && !/\.(?:png|jpe?g|gif|webp|woff2?|ico|pdf|zip)$/i.test(path));
const additionalPaths = [...newSourcePaths, ...['apps/console-api/dist', 'apps/console-web/dist', 'apps/portal-web/dist', 'playwright-report']
  .flatMap(files)];
const scan = findSecretArtifacts(secrets, additionalPaths);
const result = { stage, performedAt: new Date().toISOString(), kind: 'deployment-environment-secret-artifact-scan', allPassed: scan.leaks.length === 0, privateEnvironmentFilesLoaded: environmentFiles, coveredEnvironmentSecretCount: secrets.length, monitoringTokenFileCount, rawIngestRequiresSeparatePrivateRuntimeScan: true, nestedIdentityProviderSecretsIncluded: true, newlyAddedSourceFilesIncluded: true, coversSyntheticTestCredentials: false, syntheticCredentialsRequireSeparateOwnerScan: true, ...scan };
const directory = resolve('artifacts', stage);
await mkdir(directory, { recursive: true });
await writeFile(resolve(directory, 'environment-secret-artifact-scan.json'), `${JSON.stringify(result, null, 2)}\n`);
// Paths and counts are safe diagnostics. Never print any searched secret value.
console.log(JSON.stringify({ stage, scannedFiles: scan.scannedFiles, embeddedFiles: scan.embeddedFiles, leaks: scan.leaks, allPassed: result.allPassed }));
if (!result.allPassed) process.exitCode = 1;

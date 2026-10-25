import { execFileSync, spawnSync } from 'node:child_process';

/** Discover the actual Compose project from its running API. This deliberately
 * avoids reconstructing incomplete overlay/profile arguments during a gate. */
export function verifyM6RuntimeLogs(h) {
  h.requireLive();
  const exec = args => execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 32 * 1024 * 1024 });
  const apiId = exec(['compose', 'ps', '-q', 'console-api']).trim();
  if (!/^[a-f\d]{12,64}$/.test(apiId)) throw new Error('running API identity could not be resolved');
  const project = exec(['inspect', '-f', '{{index .Config.Labels "com.docker.compose.project"}}', apiId]).trim();
  if (!/^[a-z\d_-]{1,100}$/i.test(project)) throw new Error('actual Compose project label is invalid');
  const encoded = (h.referenceData.tokens ?? []).filter(row => row.purpose === 'collector_ingest').flatMap(row => { const value = Buffer.from(`kongos:${row.token}`).toString('base64'); return [value, `Basic ${value}`]; });
  const tokens = [...new Set([...h.secrets, ...encoded].filter(value => typeof value === 'string' && value.length >= 8))];
  const rows = [];
  const primary=h.referenceData.portalTestTargets?.primary;
  const isolated=primary&&/^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i.test(primary.id??'')&&!['dff45535-ed8d-4851-b7a6-6376feac7f59','d1dfaec8-2a10-4170-8a15-20a600a4bd4f'].includes(primary.id)&&primary.adminUrl==='http://kong-portal-admin-endpoint:8001'&&primary.proxyOrigin==='http://127.0.0.1:10000';
  if(primary)h.check(Boolean(isolated),'Logs/Runtime','isolated log scope is the trusted exact distinct C3 endpoint and proxy');
  const services=['kong','kong-secondary',...(isolated?['kong-portal']:[]),'console-api','console-web','portal-web','telemetry-collector'];
  for (const service of services) {
    const ids = exec(['ps', '--filter', `label=com.docker.compose.project=${project}`, '--filter', `label=com.docker.compose.service=${service}`, '--format', '{{.ID}}']).trim().split('\n').filter(Boolean);
    h.check(ids.length === 1, 'Logs/Runtime', `${service} has exactly one actual running container`);
    const result = spawnSync('docker', ['logs', '--since', h.referenceData.liveStartedAt, ids[0]], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 32 * 1024 * 1024 });
    // Docker logs writes container stderr to command stderr, even on exit0.
    // Capture both channels before any diagnostic is emitted.
    if (result.status !== 0 || result.error) throw new Error('runtime log collection failed; raw diagnostic withheld');
    const logged = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    rows.push({ service, knownSecretDetected: tokens.some(value => logged.includes(value)) });
  }
  for (const row of rows) h.check(row.knownSecretDetected === false, 'Logs/Redaction', `${row.service} log contains no captured password, session, API Key or current telemetry token`);
  return { services: rows, since: h.referenceData.liveStartedAt, allPassed: rows.every(row => !row.knownSecretDetected), rawLogsPublished: false };
}

import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

// Cached image only; no Compose, live-container exec, image pull or host ports.
const root = process.cwd();
const output = resolve(root, 'artifacts/M8/snapshots-shared-route-nginx-syntax.json');
const snapshot = JSON.parse(readFileSync(resolve(root, 'artifacts/M8/reciprocal-binding-repair-after.json'), 'utf8'));
const image = snapshot.core.services.find((row) => row.name === 'console-web')?.image;
if (!/^sha256:[0-9a-f]{64}$/.test(image ?? '')) throw new Error('CACHED_NGINX_IMAGE_INVALID');
const env = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete env[key];
const scratch = mkdtempSync(resolve(tmpdir(), 'kongos-m8-nginx-syntax-'));
const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const report = {
  isolated: true, image, user: '101:101', network: 'none', readOnly: true,
  existingServiceMutations: 0, hostPorts: 0, builds: 0, pulls: 0,
  publicConfigurationCopies: '0444; source bytes unchanged; equivalent to Dockerfile COPY --chmod=0644 readability',
  checks: [], allPassed: false,
};
let failure;
try {
  chmodSync(scratch, 0o755);
  // Source checkout permissions may be 0600. Model image COPY --chmod
  // without mutating the checked-in files or reading any live configuration.
  for (const config of ['console-nginx.conf', 'default.conf', 'console-production.conf']) {
    copyFileSync(resolve(root, 'deploy/nginx', config), resolve(scratch, config));
    chmodSync(resolve(scratch, config), 0o444);
    if (sha(resolve(scratch, config)) !== sha(resolve(root, 'deploy/nginx', config))) throw new Error('PUBLIC_CONFIGURATION_COPY_MISMATCH');
  }
  // Disposable local certificate: never read any production TLS material.
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=source-only.invalid', '-keyout', resolve(scratch, 'tls.key'),
    '-out', resolve(scratch, 'tls.crt')], { stdio: 'ignore', timeout: 15000 });
  chmodSync(resolve(scratch, 'tls.key'), 0o444);
  chmodSync(resolve(scratch, 'tls.crt'), 0o444);
  for (const config of ['default.conf', 'console-production.conf']) {
    const name = `kongos-m8-nginx-syntax-${randomUUID()}`;
    const args = ['--host=unix:///var/run/docker.sock', 'run', '--rm', '--pull=never',
      '--name', name, '--network', 'none', '--user', '101:101', '--read-only',
      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m,mode=1777', '--add-host', 'console-api:127.0.0.1',
      '--mount', `type=bind,src=${resolve(scratch, 'console-nginx.conf')},dst=/etc/nginx/nginx.conf,readonly`,
      '--mount', `type=bind,src=${resolve(scratch, config)},dst=/etc/nginx/conf.d/default.conf,readonly`,
      '--mount', `type=bind,src=${scratch},dst=/run/kongos-tls,readonly`,
      '--entrypoint', 'nginx', image, '-t'];
    let passed = false;
    let exitCode = 1;
    try {
      const result = execFileSync('docker', args, { env, timeout: 30000, maxBuffer: 32768, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      void result;
      exitCode = 0;
      passed = true;
    } catch (error) {
      exitCode = Number.isInteger(error.status) ? error.status : 1;
      failure = 'ISOLATED_NGINX_SYNTAX_FAILED';
    } finally {
      // Only this uniquely named disposable container can be removed.
      try { execFileSync('docker', ['--host=unix:///var/run/docker.sock', 'rm', '-f', name], { env, timeout: 10000, stdio: 'ignore' }); } catch {}
    }
    report.checks.push({ config: `deploy/nginx/${config}`, sha256: sha(resolve(root, 'deploy/nginx', config)), exitCode, passed });
    if (!passed) break;
  }
  report.allPassed = report.checks.length === 2 && report.checks.every((row) => row.passed);
} catch {
  failure ??= 'ISOLATED_NGINX_SYNTAX_SETUP_FAILED';
} finally {
  rmSync(scratch, { recursive: true, force: true });
  writeFileSync(output, JSON.stringify({ ...report, ...(failure ? { errorCode: failure } : {}) }, null, 2) + '\n', { flag: 'wx' });
}
console.log(JSON.stringify({ allPassed: report.allPassed, checks: report.checks.length, output: 'artifacts/M8/snapshots-shared-route-nginx-syntax.json', ...(failure ? { errorCode: failure } : {}) }));
if (!report.allPassed) process.exitCode = 1;

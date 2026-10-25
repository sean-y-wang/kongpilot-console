import { execFileSync } from 'node:child_process';
import { mkdirSync, chmodSync, readdirSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

execFileSync('npm', ['run', 'build'], { stdio: 'inherit' });
// This mountpoint must exist before a child SQL bind is mounted under read-only dist.
mkdirSync(resolve('apps/console-api/dist/infrastructure/migrations'), { recursive: true });
function readableTree(directory) {
  chmodSync(directory, 0o755);
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) readableTree(path);
    else if (entry.isFile()) chmodSync(path, 0o644);
  }
}
// Nginx's unprivileged worker must read host-built assets even with umask 077.
for (const directory of ['apps/console-api/dist', 'apps/console-web/dist', 'apps/console-api/src/infrastructure/migrations']) readableTree(resolve(directory));
if (existsSync('apps/portal-web/dist')) readableTree(resolve('apps/portal-web/dist'));
// The standalone collector binds only public executable source, never secrets.
if (existsSync('deploy/metrics-collector')) readableTree(resolve('deploy/metrics-collector'));
// Synthetic receivers bind public source as UID1000; a restrictive host umask
// must not make those modules unreadable behind the read-only source mount.
if (existsSync('deploy/event-receivers')) readableTree(resolve('deploy/event-receivers'));
// Docker's Kong user must also read new bind-mounted scripts under umask077.
for (const file of ['deploy/scripts/kong-start.sh', 'deploy/scripts/kong-secondary-start.sh',
  'deploy/scripts/kong-secure-start.sh', 'deploy/scripts/kong-migrate.sh', 'deploy/nginx/default.conf']) chmodSync(resolve(file), 0o644);
for(const file of ['deploy/nginx/portal.conf','deploy/nginx/portal-nginx.conf'])if(existsSync(file))chmodSync(resolve(file),0o644);
console.log('Compiled API/Web and prepared read-only migration mountpoint. No container changed.');

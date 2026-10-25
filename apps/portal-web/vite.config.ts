import react from '@vitejs/plugin-react';
import { chmodSync, existsSync, lstatSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
function readable(path: string) { const stat = lstatSync(path); if (stat.isSymbolicLink()) return; if (stat.isDirectory()) { chmodSync(path, 0o755); for (const name of readdirSync(path)) readable(resolve(path, name)); } else if (stat.isFile()) chmodSync(path, 0o644); }
export default { plugins: [react(), { name: 'public-artifact-permissions', closeBundle() { const dist = resolve(fileURLToPath(new URL('.', import.meta.url)), 'dist'); if (existsSync(dist)) readable(dist); } }], server: { host: '0.0.0.0', port: 8082, proxy: { '^/api/v1/portal(?:/|$)': { target: process.env.API_PROXY_TARGET ?? 'http://localhost:3000', changeOrigin: false } } }, build: { sourcemap: false, chunkSizeWarningLimit: 1500 } };

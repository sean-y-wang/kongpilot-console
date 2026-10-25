import react from '@vitejs/plugin-react';
import { chmodSync, existsSync, lstatSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function publicArtifactPermissions(path: string) {
  const stats = lstatSync(path);
  if (stats.isSymbolicLink()) return;
  if (stats.isDirectory()) {
    chmodSync(path, 0o755);
    for (const name of readdirSync(path)) publicArtifactPermissions(resolve(path, name));
  } else if (stats.isFile()) chmodSync(path, 0o644);
}

export default {
  plugins: [react(), { name: 'public-artifact-permissions', closeBundle() {
    const outputDirectory = resolve(fileURLToPath(new URL('.', import.meta.url)), 'dist');
    if (existsSync(outputDirectory)) publicArtifactPermissions(outputDirectory);
  } }],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '^/api(?:/|$)': { target: process.env.API_PROXY_TARGET ?? 'http://localhost:3000', changeOrigin: true },
      '/docs': { target: process.env.API_PROXY_TARGET ?? 'http://localhost:3000', changeOrigin: true },
    },
  },
  build: { sourcemap: false, chunkSizeWarningLimit: 1500 },
};

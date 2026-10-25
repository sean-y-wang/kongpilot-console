import { execFileSync, spawn } from 'node:child_process';
// Nest dependency injection needs TypeScript's emitted decorator metadata.
execFileSync('npx', ['tsc', '-p', 'tsconfig.json'], { stdio: 'inherit' });
const compiler = spawn('npx', ['tsc', '-p', 'tsconfig.json', '--watch', '--preserveWatchOutput'], { stdio: 'inherit' });
const server = spawn(process.execPath, ['--watch', 'dist/main.js'], { stdio: 'inherit' });
let stopping = false;
function stop(code = 0) { if (stopping) return; stopping = true; compiler.kill('SIGTERM'); server.kill('SIGTERM'); process.exitCode = code; }
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => stop());
for (const child of [compiler, server]) child.on('exit', code => stop(code || 0));

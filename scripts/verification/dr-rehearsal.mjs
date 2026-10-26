#!/usr/bin/env node
/**
 * KP-010 geographic DR *rehearsal* (docs/manuals/platform-recovery-runbook.md).
 * Same-host second-env (kp010) ≠ geographic DR. This script inventories prerequisites,
 * probes existing kp010 stacks if present, and emits an operator checklist for a true
 * off-host rehearsal. No destructive restore; never sets commercialClosed.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const outDir = resolve(process.env.KP010_GEO_OUT || join(repo, 'artifacts/M11/runs/20261025-geo-dr-rehearsal'));
const startedAt = new Date().toISOString();
const checks = [];
const record = (id, passed, detail = {}) => checks.push({ id, passed: !!passed, at: new Date().toISOString(), ...detail });

function docker(args) {
  const r = spawnSync('docker', ['--host=unix:///var/run/docker.sock', ...args], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  return { status: r.status ?? 1, stdout: r.stdout || '', stderr: r.stderr || '' };
}

mkdirSync(outDir, { recursive: true });

const runbook = join(repo, 'docs/manuals/platform-recovery-runbook.md');
const ops = join(repo, 'docs/manuals/production-operations-guide.md');
const recoveryScript = join(repo, 'deploy/scripts/platform-recovery.mjs');
const kp010Script = join(repo, 'scripts/verification/platform-restore-second-env.mjs');
const priorEvidence = join(repo, 'artifacts/M11/runs/20261024-kp010-restore/kp010-platform-second-env-restore-evidence.json');

record('runbook_present', existsSync(runbook), { path: 'docs/manuals/platform-recovery-runbook.md' });
record('ops_guide_present', existsSync(ops));
record('platform_recovery_script', existsSync(recoveryScript));
record('kp010_second_env_script', existsSync(kp010Script));

let prior = null;
if (existsSync(priorEvidence)) {
  prior = JSON.parse(readFileSync(priorEvidence, 'utf8'));
  record('prior_second_env_evidence', prior.allCriticalPassed === true && prior.commercialClosed === false, {
    checks: (prior.checks || []).length,
    commercialClosed: prior.commercialClosed,
    note: 'same-host second volumes; not geographic',
  });
} else {
  record('prior_second_env_evidence', false, { missing: true });
}

const projects = ['kp010src', 'kp010dst'];
const projectStatus = {};
for (const project of projects) {
  const ps = docker(['ps', '-a', '--filter', `label=com.docker.compose.project=${project}`, '--format', '{{.Names}}\t{{.Status}}']);
  const rows = ps.stdout.trim().split('\n').filter(Boolean).map((l) => {
    const [name, ...rest] = l.split('\t');
    return { name, status: rest.join('\t') };
  });
  projectStatus[project] = { containerCount: rows.length, rows };
  record(`project_${project}_visible`, rows.length > 0, { containerCount: rows.length });
}

// Non-destructive health probes on known containers
const probes = [];
for (const name of ['kp010src-console-db-1', 'kp010dst-console-db-1', 'kp010src-redis-1', 'kp010dst-redis-1']) {
  const insp = docker(['inspect', '--format', '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}', name]);
  const [state, health] = (insp.stdout.trim() || 'missing|none').split('|');
  const ok = insp.status === 0 && (state === 'running');
  probes.push({ name, state, health, ok });
  record(`probe_${name}`, ok, { state, health });
}

const operatorChecklist = [
  { step: 1, owner: 'operator (need second host)', action: 'Provision independent host/permission domain with Docker; import immutable image IDs (--pull=never)' },
  { step: 2, owner: 'operator', action: 'Retrieve backup archive + BACKUP_ENCRYPTION_KEY + CONSOLE_ENCRYPTION_KEY from separate custody (not colocated with dump)' },
  { step: 3, owner: 'operator', action: 'Create NEW siteId/project/volumes; refuse source project reuse; run platform-recovery restore' },
  { step: 4, owner: 'operator', action: 'Under recovery gate: verify SQL checksums, audit chain heads, ciphertext samples; fresh Redis (no old locks/tokens)' },
  { step: 5, owner: 'operator', action: 'Record RPO = last confirmed source write − restore point; RTO = command start → safe business takeover (not pg_restore alone)' },
  { step: 6, owner: 'operator + need-browser', action: 'Controlled local login + read-only Console checks; no Kong writes until explicit cutover' },
  { step: 7, owner: 'operator', action: 'Document cutover / rollback; keep commercialClosed=false until full matrix passes' },
];

const geographicClaimed = false;
const allPassed = checks.filter((c) => c.id.startsWith('runbook') || c.id.startsWith('platform') || c.id.startsWith('kp010') || c.id.startsWith('prior')).every((c) => c.passed)
  && probes.some((p) => p.ok);

const report = {
  schemaVersion: 1,
  kind: 'kp010-geographic-dr-rehearsal',
  commercialClosed: false,
  geographicDrClosed: false,
  geographicClaimed,
  sameHostSecondEnvIsNotGeographic: true,
  allPassed,
  startedAt,
  completedAt: new Date().toISOString(),
  timezoneNote: 'Asia/Shanghai (UTC+8)',
  references: {
    runbook: 'docs/manuals/platform-recovery-runbook.md',
    opsGuide: 'docs/manuals/production-operations-guide.md',
    priorSecondEnv: priorEvidence,
    recoveryScript: 'deploy/scripts/platform-recovery.mjs',
  },
  projectStatus,
  probes,
  operatorChecklist,
  remainingForClosure: [
    'True off-host restore with independent image import + key custody',
    'Measured RPO/RTO including application verification and safe takeover',
    'Post-restore business/credential proxy on restored API',
    'Cutover rehearsal with browser matrix (owner: need-browser)',
  ],
  checks,
};
writeFileSync(join(outDir, 'kp010-geographic-dr-rehearsal-evidence.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({
  allPassed, geographicDrClosed: false, commercialClosed: false,
  probesOk: probes.filter((p) => p.ok).length, checklistSteps: operatorChecklist.length,
  out: join(outDir, 'kp010-geographic-dr-rehearsal-evidence.json'),
}, null, 2));
process.exit(allPassed ? 0 : 1);

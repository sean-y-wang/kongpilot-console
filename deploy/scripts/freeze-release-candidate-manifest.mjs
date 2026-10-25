#!/usr/bin/env node
import { tmpdir } from 'node:os';
/**
 * Freeze a *candidate* release package per ReleaseV1_0-platform-closure-plan.md
 * (deploy/releases/.../manifest.json contract). Local: source tarball + checksums +
 * images list. Full SBOM/Grype is the CI recipe deploy/scripts/ci-images.mjs
 * (immutable-images-amd64; GitHub-hosted amd64 only). Never sets commercialClosed.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const fail = (c) => { throw new Error(c); };
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const shaFile = (p) => sha256(readFileSync(p));

function sh(cmd, args) {
  const r = spawnSync(cmd, args, { cwd: repo, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  if (r.status !== 0) fail(`FREEZE_CMD_FAILED:${cmd}`);
  return (r.stdout || '').trim();
}

const revision = sh('git', ['rev-parse', 'HEAD']);
const short = revision.slice(0, 12);
const branch = sh('git', ['rev-parse', '--abbrev-ref', 'HEAD']);
const commitTime = sh('git', ['show', '-s', '--format=%cI', 'HEAD']);
const dirty = sh('git', ['status', '--porcelain']);
if (dirty) fail('FREEZE_WORKING_TREE_DIRTY');

const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
const candidateId = `${stamp}-${short}`;
const outDir = join(repo, 'deploy/releases/candidates', candidateId);
if (existsSync(outDir)) fail('FREEZE_CANDIDATE_DIR_EXISTS');
mkdirSync(outDir, { recursive: true, mode: 0o755 });

const lockSha = shaFile(join(repo, 'package-lock.json'));
const rootPkg = JSON.parse(readFileSync(join(repo, 'package.json'), 'utf8'));
const nodePin = readFileSync(join(repo, '.node-version'), 'utf8').trim();

const migDir = join(repo, 'apps/console-api/src/infrastructure/migrations');
const sql = readdirSync(migDir).filter((n) => n.endsWith('.sql')).sort()
  .map((name) => ({ name, sha256: shaFile(join(migDir, name)) }));

const trackedFiles = [
  'apps/console-api/Dockerfile',
  'apps/console-web/Dockerfile',
  'apps/portal-web/Dockerfile',
  'deploy/compose.production.yml',
  'deploy/compose.external-kong.yml',
  'deploy/production.env.example',
  'deploy/images/toolchain.json',
  'deploy/security/image-vulnerability-acceptance.json',
  'deploy/scripts/ci-images.mjs',
  'deploy/scripts/scan-commercial-images.mjs',
];
const fileDigests = trackedFiles.filter((f) => existsSync(join(repo, f)))
  .map((path) => ({ path, sha256: shaFile(join(repo, path)) }));

const images = [];
const docker = spawnSync('docker', ['images', '--format', '{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Digest}}'], { encoding: 'utf8' });
if (docker.status === 0) {
  for (const line of docker.stdout.split('\n').filter(Boolean)) {
    const [repository, tag, id, digest] = line.split('\t');
    if (/kongpilot|kongos|kpapi|kpportal|console-api|console-web|portal-web/i.test(`${repository}:${tag}`)) {
      images.push({ repository, tag, imageId: id, digest: digest === '<none>' ? null : digest });
    }
  }
}

// Tracked-source tarball via git archive (reproducible; excludes untracked secrets)
const tarballName = `kongpilot-console-${candidateId}-source.tar.gz`;
// Keep large tarball off-repo by default (audited via SHA256SUMS); override with FREEZE_TARBALL_DIR.
const tarballDir = process.env.FREEZE_TARBALL_DIR
  ? resolve(process.env.FREEZE_TARBALL_DIR)
  : join(tmpdir(), 'kongpilot-release-candidates', candidateId);
mkdirSync(tarballDir, { recursive: true, mode: 0o755 });
const tarballPath = join(tarballDir, tarballName);
const ga = spawnSync('git', ['archive', '--format=tar.gz', '-o', tarballPath, 'HEAD'], { cwd: repo, encoding: 'utf8' });
if (ga.status !== 0) fail('FREEZE_TARBALL_FAILED');
const tarballSha = shaFile(tarballPath);
const tarballBytes = statSync(tarballPath).size;
const tarMethod = 'git-archive';
const tarballStoredInGit = false;

const sbomRecipe = {
  workflowJob: 'immutable-images-amd64',
  script: 'deploy/scripts/ci-images.mjs',
  scanner: 'deploy/scripts/scan-commercial-images.mjs',
  toolchain: 'deploy/images/toolchain.json',
  constraint: 'GitHub-hosted linux/amd64 only (assertHostedAmd64); local box cannot claim final SBOM',
  localSbomExecuted: false,
  note: 'Candidate freeze records the recipe; final SBOM/checksums attach after green immutable-images on this revision',
};

const manifest = {
  format: 'kongpilot-release-candidate-manifest-v1',
  commercialClosed: false,
  commercialAcceptance: false,
  candidateId,
  versionDeclared: rootPkg.version,
  productDisplayHint: 'v1.0 (UI display ≠ GA tag)',
  branch,
  commit: revision,
  commitTime,
  nodeVersionPin: nodePin,
  lockfileSha256: lockSha,
  sqlMigrations: sql,
  sqlCount: sql.length,
  fileDigests,
  localImagesInventory: images,
  sourceTarball: { name: tarballName, sha256: tarballSha, bytes: tarballBytes, method: tarMethod, storedInGit: tarballStoredInGit, localPathHint: tarballPath },
  sbom: sbomRecipe,
  knownLimitations: [
    'Not a GA freeze; commercialClosed remains false',
    'Local images inventory may be empty or lab-only; registry digests absent',
    'SBOM/Grype not executed in this candidate step',
    'Working tree was clean at freeze; subsequent commits invalidate this candidate',
  ],
  frozenAt: new Date().toISOString(),
  timezoneNote: 'Asia/Shanghai (UTC+8)',
};

writeFileSync(join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o644 });
writeFileSync(join(outDir, 'SHA256SUMS'), [
  `${tarballSha}  ${tarballName}`,
  `${shaFile(join(outDir, 'manifest.json'))}  manifest.json`,
  ...sql.map((s) => `${s.sha256}  sql/${s.name}`),
].join('\n') + '\n', { mode: 0o644 });

console.log(JSON.stringify({
  candidateId, outDir: relative(repo, outDir), commit: short,
  sqlCount: sql.length, tarballBytes, tarballSha: tarballSha.slice(0, 16),
  localImages: images.length, commercialClosed: false,
}, null, 2));

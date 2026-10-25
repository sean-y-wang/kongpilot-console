import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Offline generator regression: temporary credentials never enter evidence.
// Existing account/environment passwords are deliberately left unchanged.
const checks = [];
const directory = mkdtempSync(join(tmpdir(), 'kongos-env-check-'));
const before = existsSync('.env') ? createHash('sha256').update(readFileSync('.env')).digest('hex') : null;
const passwords = [];
function check(name, passed) { checks.push({ name, passed: Boolean(passed) }); }
function values(path) {
  return Object.fromEntries(readFileSync(path, 'utf8').trim().split('\n').map(line => {
    const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)];
  }));
}
let failed;
try {
  for (let i = 0; i < 4; i++) {
    const path = join(directory, `primary-${i}.env`);
    const output = execFileSync(process.execPath, ['deploy/scripts/generate-env.mjs', path], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
    const content = readFileSync(path);
    const env = values(path), password = env.BOOTSTRAP_ADMIN_PASSWORD;
    passwords.push(password);
    check(`generated primary${i} is mode0600`, (statSync(path).mode & 0o777) === 0o600);
    check(`generated primary${i} password meets independent UTF8/class constraints`,
      Buffer.byteLength(password) >= 12 && Buffer.byteLength(password) <= 72 &&
      /[a-z]/.test(password) && /[A-Z]/.test(password) && /\d/.test(password) && /[^A-Za-z0-9]/.test(password));
    check(`generated primary${i} secrets are not printed`, !Object.entries(env).filter(([key]) => /PASSWORD|APP_SECRET|PORTAL_SECRET|ENCRYPTION_KEY/.test(key)).some(([, value]) => output.includes(value)));
    check(`generated primary${i} Portal secret is independent256bits`, /^[a-f0-9]{64}$/.test(env.PORTAL_SECRET)&&env.PORTAL_SECRET!==env.APP_SECRET&&env.PORTAL_SECRET!==env.CONSOLE_ENCRYPTION_KEY);
    const repeated = spawnSync(process.execPath, ['deploy/scripts/generate-env.mjs', path], { encoding: 'utf8' });
    check(`existing primary${i} cannot be overwritten`, repeated.status !== 0 && readFileSync(path).equals(content));
  }
  check('independent bootstrap generations use independent random suffixes', new Set(passwords).size === 4);
  const productionPath=join(directory,'production.env');
  const missingOrigin=spawnSync(process.execPath,['deploy/scripts/generate-env.mjs',productionPath,'--production'],{encoding:'utf8'});
  check('production generator requires explicit HTTPS portal origin before any file write',missingOrigin.status===2&&!existsSync(productionPath));
  const httpOrigin=spawnSync(process.execPath,['deploy/scripts/generate-env.mjs',productionPath,'--production','--portal-origin','http://portal.example.test'],{encoding:'utf8'});
  check('production generator rejects HTTP origin before file write',httpOrigin.status===2&&!existsSync(productionPath));
  execFileSync(process.execPath,['deploy/scripts/generate-env.mjs',productionPath,'--production','--portal-origin','https://portal.example.test'],{encoding:'utf8',stdio:['pipe','pipe','pipe']});
  const productionEnv=values(productionPath);
  check('production generation pins HTTPS origin and Secure cookies',productionEnv.PORTAL_PUBLIC_ORIGINS==='https://portal.example.test'&&productionEnv.COOKIE_SECURE==='true'&&(statSync(productionPath).mode&0o777)===0o600);
  const secondary = join(directory, 'secondary.env');
  const output = execFileSync(process.execPath, ['deploy/scripts/generate-multicluster-env.mjs', secondary], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  const content = readFileSync(secondary), env = values(secondary);
  check('secondary credentials are mode0600 and have192 random bits', (statSync(secondary).mode & 0o777) === 0o600 && /^[a-f\d]{48}$/.test(env.KONG_SECONDARY_DATABASE_PASSWORD));
  check('secondary credential is not printed', !output.includes(env.KONG_SECONDARY_DATABASE_PASSWORD));
  const repeated = spawnSync(process.execPath, ['deploy/scripts/generate-multicluster-env.mjs', secondary], { encoding: 'utf8' });
  check('existing secondary credentials cannot be overwritten', repeated.status !== 0 && readFileSync(secondary).equals(content));
} catch { failed = 'GENERATOR_REGRESSION_EXCEPTION'; check('offline generator check completed', false); }
finally { rmSync(directory, { recursive: true, force: true }); }
check('actual primary environment credentials remain unchanged', before === (existsSync('.env') ? createHash('sha256').update(readFileSync('.env')).digest('hex') : null));
const result = { performedAt: new Date().toISOString(), kind: 'offline-environment-generation',
  existingAccountPasswordChanged: false, temporaryCredentialDirectoryRemoved: !existsSync(directory),
  checks, allPassed: checks.every(c => c.passed), ...(failed ? { code: failed } : {}) };
const stage=process.argv[2]||'M4';
if(!/^M(?:[0-9]|1[01])$/.test(stage)){console.error('ENVIRONMENT_GENERATION_STAGE_INVALID');process.exit(2);}
mkdirSync(`artifacts/${stage}`, { recursive: true });
writeFileSync(`artifacts/${stage}/environment-generation.json`, JSON.stringify({...result,stage}, null, 2) + '\n');
console.log(`${checks.filter(c => c.passed).length}/${checks.length} offline environment-generation checks passed; no credential values recorded.`);
if (!result.allPassed) process.exitCode = 1;

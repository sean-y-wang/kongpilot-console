import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

let requestedTarget,requestedOrigin,production=false;
const args=process.argv.slice(2);
for(let index=0;index<args.length;index++){
  const arg=args[index];
  if(arg==='--production')production=true;
  else if(arg==='--portal-origin'){if(requestedOrigin!==undefined||!args[index+1]){console.error('ENVIRONMENT_GENERATOR_ARGUMENTS_INVALID');process.exit(2);}requestedOrigin=args[++index];}
  else if(arg.startsWith('-')||requestedTarget!==undefined){console.error('ENVIRONMENT_GENERATOR_ARGUMENTS_INVALID');process.exit(2);}
  else requestedTarget=arg;
}
const target = resolve(requestedTarget || '.env');
if(requestedOrigin&&!production){console.error('PRODUCTION_PORTAL_HTTPS_ORIGIN_REQUIRED');process.exit(2);}
let portalOrigins='http://127.0.0.1:8082,http://localhost:8082';
if(production){
  const origin=requestedOrigin;
  try{const url=new URL(origin||'');if(url.protocol!=='https:'||url.origin!==origin||url.username||url.password)throw new Error();portalOrigins=url.origin;}catch{console.error('PRODUCTION_PORTAL_HTTPS_ORIGIN_REQUIRED');process.exit(2);}
}
const lines = {
  KONG_DATABASE_PASSWORD: randomBytes(24).toString('hex'),
  CONSOLE_DATABASE_PASSWORD: randomBytes(24).toString('hex'),
  CONSOLE_APP_PASSWORD: randomBytes(24).toString('hex'),
  REDIS_PASSWORD: randomBytes(24).toString('hex'),
  BOOTSTRAP_ADMIN_USERNAME: 'admin',
  // The public prefix guarantees all policy classes; the suffix adds192-bit entropy.
  BOOTSTRAP_ADMIN_PASSWORD: `KongPilot!9${randomBytes(24).toString('base64url')}`,
  CONSOLE_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
  APP_SECRET: randomBytes(32).toString('hex'),
  PORTAL_SECRET: randomBytes(32).toString('hex'),
  PORTAL_PUBLIC_ORIGINS: portalOrigins,
  PORTAL_WEB_PORT: '8082',
  CONSOLE_WEB_PORT: '8080',
  KONG_PROXY_PORT: '8000',
  COOKIE_SECURE: production?'true':'false',
  OUTBOUND_ALLOWED_HOSTS: 'kong,prometheus,loki,mock-kong,localhost,127.0.0.1',
  LOG_LEVEL: 'info',
};
// Never overwrite a existing credential file. Never print credential values.
writeFileSync(target, Object.entries(lines).map(([key, value]) => `${key}=${value}`).join('\n') + '\n', { mode: 0o600, flag: 'wx' });
console.log(`Generated ${target} (mode 0600). Retrieve bootstrap password locally from that file.`);

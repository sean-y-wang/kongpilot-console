import {ensurePortalEnvironment} from './portal-environment.mjs';
try{const result=ensurePortalEnvironment(process.argv[2]||'.env');console.log(JSON.stringify(result));}catch{console.error('PORTAL_ENV_PREPARATION_FAILED; existing secrets were not printed or replaced.');process.exitCode=1;}

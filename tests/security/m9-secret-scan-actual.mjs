import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync,lstatSync,readFileSync,realpathSync,readdirSync,mkdirSync,writeFileSync } from 'node:fs';
import { dirname,resolve,relative,sep } from 'node:path';
import { parse } from 'yaml';
import { collectSecretMaterial,buildSecretMatcher,secretScannerSelfTest,excludeControlledRejectedDraftProbe } from './lib/m9-secret-scan.mjs';

if(process.argv.includes('--self-test')){process.stdout.write(JSON.stringify(secretScannerSelfTest())+'\n');process.exit(0);}
const repository=resolve(dirname(new URL(import.meta.url).pathname),'../..');
const privateDirectory='/dev/shm/kongpilot-release-lab';
const reportPath=resolve(repository,'artifacts/M9/secret-scan-verification.json');
const ownedContainers=['console-api','console-db','redis','kong','kong-db','echo','console-migrations'].map(name=>`kongpilot-release-lab-${name}-1`);
const findings=[],checks=[],fileGroups={repository:0,'console-api-dist':0,'console-web-dist':0,'portal-web-dist':0,'owned-container-log':0,'owned-audit-records':0};
let passed=false,scanBytes=0,secretCount=0,patternCount=0,failure,unknownOriginalResponses=0,retainedFailedOriginalRequests=0,excludedNonCredentialProbes=[];
const guardPrivate=path=>{
  const stat=lstatSync(path);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o600)throw Error('PRIVATE_MATERIAL_FILE_REQUIRED');
  if(stat.size>32*1024*1024)throw Error('PRIVATE_MATERIAL_FILE_SIZE_BUDGET');
  return readFileSync(path,'utf8');
};
const check=(name,condition=true)=>{assert(condition,name);checks.push({name,passed:true});};
const docker=args=>{
  const result=spawnSync('docker',['--host=unix:///var/run/docker.sock','exec','--env','GOMAXPROCS=2','kongos-ram-tool-m08-20261012-a3',
    'docker','--host=unix:///run/docker-production.sock',...args],{env:{...process.env,GOMAXPROCS:'2'},encoding:null,timeout:20000,maxBuffer:64*1024*1024});
  if(result.error||result.status!==0)throw Error('OWNED_LAB_LOG_READ_FAILED');
  // Docker sends a container's stderr stream to stderr even on success.
  return Buffer.concat([result.stdout??Buffer.alloc(0),Buffer.from('\n'),result.stderr??Buffer.alloc(0)]);
};
try{
  check('explicit final release evidence handoff required',process.env.RELEASE_LAB_READY==='true'&&process.env.RELEASE_LAB_SECRET_SCAN_READY==='true');
  const verifiedAfter=process.env.RELEASE_LAB_VERIFIED_AFTER;
  check('current source deployment timestamp is explicit',typeof verifiedAfter==='string'&&/^\d{4}-\d\d-\d\dT/.test(verifiedAfter)&&Number.isFinite(Date.parse(verifiedAfter)));
  const harness=JSON.parse(guardPrivate(`${privateDirectory}/m9-harness.json`));
  check('native milestone and real lab cluster match',harness.milestone==='M9'&&harness.cid==='e269f167-53e9-4895-af89-5b1b8835c6ec');
  const browser=JSON.parse(guardPrivate(`${privateDirectory}/m9-browser-journal.json`));
  const browserMaterial=JSON.parse(guardPrivate(`${privateDirectory}/m9-browser-secret-material.json`));
  check('native and browser originals retained',Array.isArray(harness.requests)&&Array.isArray(browser.requests));
  const environment=Object.fromEntries(guardPrivate(`${privateDirectory}/lab.env`).trim().split('\n').filter(Boolean).map(line=>{
    const at=line.indexOf('=');assert(at>0);return[line.slice(0,at),line.slice(at+1)];
  }));
  let material={...harness,requests:[...harness.requests,...browser.requests]};
  unknownOriginalResponses=material.requests.filter(packet=>['prepared','response_unknown'].includes(packet.state)).length;
  retainedFailedOriginalRequests=material.requests.filter(packet=>typeof packet.status==='number'&&packet.status>=400).length;
  const originalLedgerBytes=readFileSync(`${privateDirectory}/m9-harness.json`);
  const controlled=excludeControlledRejectedDraftProbe(material,environment,browserMaterial,readFileSync(resolve(repository,'tests/security/m9-native-actual.mjs'),'utf8'),{
    index:19,requestId:'66ec1477-bb22-495d-b6cd-1791eff547ef',actorId:'f5738365-97c4-44af-abdb-0262c5104376',method:'POST',startedAt:'2026-10-12T17:30:43.812Z',
    path:'/clusters/e269f167-53e9-4895-af89-5b1b8835c6ec/drafts?workspaceId=b3b08a5e-bdeb-478a-90df-39547799bb82',
    sourcePath:'tests/security/m9-native-actual.mjs',sourceByteOffset:5639,
  });
  material=controlled.material;excludedNonCredentialProbes.push(controlled.evidence);
  check('one public rejection probe is exact source-linked and absent from all issued/private materials',controlled.evidence.sourceLiteralLinked&&controlled.evidence.issuedFixtureCredentialMatch===false);
  check('original private ledger is byte-for-byte unchanged',readFileSync(`${privateDirectory}/m9-harness.json`).equals(originalLedgerBytes));
  // Export packets may contain credentials nested in decK YAML. They remain private.
  const privateExports=[];
  for(const packet of material.requests)if(typeof packet.rawResponseText==='string'&&packet.rawResponseText.includes('_format_version:')){
    privateExports.push(parse(packet.rawResponseText));
  }
  const secrets=collectSecretMaterial(material,environment,{browser:browserMaterial,exports:privateExports});
  secretCount=secrets.length;
  check('actual passwords, API Keys, cookies and CSRF are included',
    ['password','api-key','cookie','csrf','environment-secret'].every(kind=>secrets.some(row=>row.kinds.includes(kind))));
  const idempotencyKeys=new Set(material.requests.map(packet=>packet.key??packet.idempotencyKey).filter(Boolean));
  check('public idempotency ledger keys are excluded from credential material',secrets.every(row=>!idempotencyKeys.has(row.value)));
  const matcher=buildSecretMatcher(secrets);patternCount=matcher.patternCount;
  const safePath=path=>matcher.scan(Buffer.from(path)).length?'[PRIVATE_VALUE_IN_PATH]':path;
  const scan=(label,bytes,group)=>{
    scanBytes+=bytes.length;
    if(bytes.length>64*1024*1024||scanBytes>512*1024*1024)throw Error('PUBLIC_SCAN_BYTE_BUDGET');
    fileGroups[group]++;
    for(const found of matcher.scan(bytes))findings.push({path:safePath(label),...found});
  };
  const git=spawnSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:repository,encoding:'utf8',timeout:10000,maxBuffer:8*1024*1024});
  if(git.error||git.status!==0)throw Error('PUBLIC_REPOSITORY_FILE_ENUMERATION_FAILED');
  const files=new Map();
  for(const name of new Set(git.stdout.split('\0').filter(Boolean)))files.set(resolve(repository,name),{label:name,group:'repository'});
  const walk=(directory,group)=>{
    if(!existsSync(directory))throw Error('CURRENT_THREE_DIST_BUILDS_REQUIRED');
    for(const entry of readdirSync(directory,{withFileTypes:true})){
      const path=resolve(directory,entry.name);
      if(entry.isDirectory())walk(path,group);else files.set(path,{label:relative(repository,path),group});
    }
  };
  for(const [directory,group]of [['apps/console-api/dist','console-api-dist'],['apps/console-web/dist','console-web-dist'],['apps/portal-web/dist','portal-web-dist']])walk(resolve(repository,directory),group);
  if(files.size>15000)throw Error('PUBLIC_SCAN_FILE_BUDGET');
  for(const [path,descriptor]of files){
    if(!existsSync(path))continue; // A tracked deletion has no publishable file content.
    const actual=realpathSync(path);
    if(actual!==repository&&!actual.startsWith(repository+sep))throw Error('PUBLIC_SCAN_EXTERNAL_SYMLINK_REFUSED');
    if(!lstatSync(actual).isFile())continue;
    scan(descriptor.label,readFileSync(actual),descriptor.group);
  }
  check('public source/artifacts and all three current builds were scanned',Object.values(fileGroups).slice(0,4).every(count=>count>0));
  for(const container of ownedContainers){
    const name=JSON.parse(docker(['inspect','--format','{{json .Name}}',container]).toString().trim());
    if(name!==`/${container}`)throw Error('SELF_OWNED_CONTAINER_GATE_FAILED');
    scan(`docker://${container}/logs`,docker(['logs',container]),'owned-container-log');
  }
  check('complete own-lab stdout/stderr logs were included without clipping',fileGroups['owned-container-log']===ownedContainers.length);
  // Actual audit before/after/diff values are read into memory and scanned;
  // they are never written to a public file or printed in tool output.
  const auditReader=`const {Client}=require('pg');(async()=>{const u=new URL(process.env.DATABASE_URL);
    if(process.env.RELEASE_LAB_READY!=='true'||u.hostname!=='console-db'||u.port!=='5432'||u.pathname!=='/kongpilot'||u.username!=='kongpilot_lab_app')throw Error('CONSOLE_DATABASE_GATE');
    const c=new Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3000});try{await c.connect();await c.query('BEGIN READ ONLY');
    await c.query("SET LOCAL statement_timeout='5s'");const r=await c.query('SELECT * FROM audit_events WHERE chain_scope=ANY($1::text[]) ORDER BY chain_scope,sequence LIMIT 10001',[['cluster:e269f167-53e9-4895-af89-5b1b8835c6ec','global']]);
    if(r.rows.length===0||r.rows.length>10000)throw Error('AUDIT_SCAN_ROW_BUDGET');process.stdout.write(JSON.stringify(r.rows));
    }finally{await c.query('ROLLBACK').catch(()=>{});await c.end();}})().catch(()=>{process.exitCode=1;});`;
  scan('postgres://own-console/kongpilot/audit_events',docker(['exec','-e','RELEASE_LAB_READY=true','kongpilot-release-lab-console-api-1','node','-e',auditReader]),'owned-audit-records');
  check('actual own-lab audit before/after/diff values were included without publishing row content',fileGroups['owned-audit-records']===1);
  check('no current actual secret appears literally or in common encodings',findings.length===0);
  passed=true;
}catch(error){failure={code:/^[A-Z0-9_]+$/.test(error?.message??'')?error.message:error?.code==='ERR_ASSERTION'?'ASSERTION_FAILED':'SCAN_FAILED'};}
finally{
  const report={passed,milestone:'M9',environment:'self-owned RAM release lab',productionDeployment:false,credentialsRecorded:false,
    actualSecretCount:secretCount,patternCount,scannedBytes:scanBytes,fileGroups,checks,findings,
    scanScope:'git tracked and untracked publishable files, three current dist builds, all seven owned lab container stdout/stderr logs including pre-fix failures, and actual own-console audit records',
    unknownOriginalResponses,retainedFailedOriginalRequests,unknownOriginalResponsesResolved:false,excludedNonCredentialProbes,
    limits:['Binary artifacts are scanned for encoded bytes; this does not perform OCR of screenshots. Browser DOM credential exposure requires separate browser assertions.','This scans actual materials present in retained native and browser journals, not every possible credential created outside this isolated release fixture.'],
    ...(failure?{failure}:{})};
  mkdirSync(dirname(reportPath),{recursive:true});
  // Keep every earlier result, including failures, rather than replacing its evidence.
  if(existsSync(reportPath)){
    let suffix=1;while(existsSync(reportPath.replace('.json',`.attempt-${suffix}.json`)))suffix++;
    writeFileSync(reportPath.replace('.json',`.attempt-${suffix}.json`),readFileSync(reportPath));
  }
  writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n');
  process.stdout.write(JSON.stringify({passed,checks:checks.length,actualSecretCount:secretCount,patterns:patternCount,files:fileGroups,scannedBytes:scanBytes,findingCount:findings.length,...(failure?{failure}:{})})+'\n');
  if(!passed)process.exitCode=1;
}

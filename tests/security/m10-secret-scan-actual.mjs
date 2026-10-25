import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync,lstatSync,readFileSync,realpathSync,readdirSync,mkdirSync,writeFileSync } from 'node:fs';
import { dirname,resolve,relative,sep } from 'node:path';
import { parse } from 'yaml';
import { buildSecretMatcher,collectSecretMaterial,secretScannerSelfTest } from './lib/m9-secret-scan.mjs';
import { M10_CONTROL_ID_PROOF_PATH,m10ClusterIds,m10SecretMaterial,retainedM9ScanMaterial,m10DockerEnvironment } from './lib/m10-release-evidence.mjs';
import { M10_AUTH_JOURNAL_EVIDENCE_PATH,M10_AUTH_JOURNAL_EVIDENCE_SHA256,M10_AUTH_JOURNAL_LIMITATION,m10BrowserContinuationRootPacket,m10FinalBrowserEvidenceNames,validateM10AuthJournalCoverage,validateM10FinalBrowserRetention } from './lib/m10-auth-journal-coverage.mjs';

if(process.argv.includes('--self-test')){process.stdout.write(JSON.stringify(secretScannerSelfTest())+'\n');process.exit(0);}
const repository=resolve(dirname(new URL(import.meta.url).pathname),'../..'),privateDirectory='/dev/shm/kongpilot-release-lab';
const reportPath=resolve(repository,'artifacts/M10/secret-scan-verification.json');
const ownedContainers=['console-api','console-db','redis','kong','kong-db','echo','console-migrations','stage-kong','stage-kong-db','stage-kong-migrations'].map(name=>`kongpilot-release-lab-${name}-1`);
const findings=[],checks=[],fileGroups={repository:0,'console-api-dist':0,'console-web-dist':0,'portal-web-dist':0,'owned-container-log':0,'owned-audit-records':0};
let passed=false,scannedBytes=0,secretCount=0,patternCount=0,failure,explicitFixtureKeyCount=0,unknownOriginalResponses=0,retainedFailedOriginalRequests=0;
let authenticationJournalCoverage,browserEvidenceRetention,controlIdentifierNormalization;
const excludedNonCredentialProbes=[];
const guardPrivate=path=>{const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o600)throw Error('PRIVATE_MATERIAL_FILE_REQUIRED');if(stat.size>32*1024*1024)throw Error('PRIVATE_MATERIAL_FILE_SIZE_BUDGET');return readFileSync(path,'utf8');};
const privateJSON=name=>JSON.parse(guardPrivate(`${privateDirectory}/${name}`));
const check=(name,condition=true)=>{assert(condition,name);checks.push({name,passed:true});};
const docker=args=>{const result=spawnSync('docker',['--host=unix:///var/run/docker.sock','exec','--env','GOMAXPROCS=2','kongos-ram-tool-m08-20261012-a3','docker','--host=unix:///run/docker-production.sock',...args],{env:m10DockerEnvironment(),encoding:null,timeout:30000,maxBuffer:64*1024*1024});if(result.error||result.status!==0)throw Error('OWNED_LAB_READ_FAILED');return Buffer.concat([result.stdout??Buffer.alloc(0),Buffer.from('\n'),result.stderr??Buffer.alloc(0)]);};
try{
 authenticationJournalCoverage=validateM10AuthJournalCoverage(readFileSync(resolve(repository,M10_AUTH_JOURNAL_EVIDENCE_PATH)));
 check('frozen historical auth-only journal coverage limitation is validated without reconstructing unavailable tokens');
 check('explicit M10 source deployment and final scan handoff',process.env.RELEASE_LAB_READY==='true'&&process.env.RELEASE_LAB_M10_DEPLOYED==='true'&&process.env.RELEASE_LAB_SECRET_SCAN_READY==='true');
 const verifiedAfter=process.env.RELEASE_LAB_VERIFIED_AFTER;check('explicit current deployment timestamp',typeof verifiedAfter==='string'&&Number.isFinite(Date.parse(verifiedAfter)));
 const harness=privateJSON('m10-harness.json'),browserFiles=m10FinalBrowserEvidenceNames(harness.browserHandoff),browser=privateJSON(browserFiles.journalName),browserMaterial=privateJSON(browserFiles.materialName),clusterIds=m10ClusterIds(harness);
 browserEvidenceRetention=validateM10FinalBrowserRetention(browserFiles,browser,browserMaterial,browserFiles.freshCycle?{
   journalBytes:Buffer.from(guardPrivate(`${privateDirectory}/m10-browser-journal.json`)),reportBytes:readFileSync(resolve(repository,'artifacts/M10/browser/verification.json')),
   materialBytes:existsSync(`${privateDirectory}/m10-browser-secret-material.json`)?Buffer.from(guardPrivate(`${privateDirectory}/m10-browser-secret-material.json`)):null,
   ...(browserFiles.readOnlyRecheck?{previousJournalBytes:Buffer.from(guardPrivate(`${privateDirectory}/m10-browser-after-visible-select-fix-journal.json`)),
     previousMaterialBytes:Buffer.from(guardPrivate(`${privateDirectory}/m10-browser-after-visible-select-fix-secret-material.json`)),
     previousReportBytes:readFileSync(resolve(repository,'artifacts/M10/browser-after-visible-select-fix/verification.json')),
     freshIntentBytes:Buffer.from(guardPrivate(`${privateDirectory}/m10-browser-fresh-intent.json`))}:{}) ,
   ...(browserFiles.verificationAttempt===2?{previousReadOnlyJournalBytes:Buffer.from(guardPrivate(`${privateDirectory}/m10-browser-readonly-recheck-journal.json`)),
     previousReadOnlyMaterialBytes:Buffer.from(guardPrivate(`${privateDirectory}/m10-browser-readonly-recheck-secret-material.json`)),
     previousReadOnlyReportBytes:readFileSync(resolve(repository,'artifacts/M10/browser-readonly-recheck/verification.json'))}:{}) ,
   ...(browser.freshCookieEvidence?{continuationRefreshBrowserBytes:Buffer.from(guardPrivate(`${privateDirectory}/m10-browser-continuation-refresh-browser.json`)),
     rawContinuationRefreshBytes:Buffer.from(guardPrivate(`${privateDirectory}/m10-browser-continuation-refresh.json`)),rootRefreshPacket:m10BrowserContinuationRootPacket(harness),
     rootRefreshMetadata:harness.browserContinuationRefresh}:{})}:{});
 check('selected final browser cycle retains exact original packets and actually issued response-cookie material');
 check('actual native and browser handoff completed',harness.browserHandoff?.nativeVerified===true&&browser.milestone==='M10'&&browser.passed===true);
 const environment=Object.fromEntries(guardPrivate(`${privateDirectory}/lab.env`).trim().split('\n').filter(Boolean).map(line=>{const at=line.indexOf('=');assert(at>0);return[line.slice(0,at),line.slice(at+1)];}));
 const legacyLedgerBytes=readFileSync(`${privateDirectory}/m9-harness.json`),legacyHarness=privateJSON('m9-harness.json'),legacyBrowser=privateJSON('m9-browser-journal.json'),legacyBrowserMaterial=privateJSON('m9-browser-secret-material.json');
 const acceptedLegacy=JSON.parse(readFileSync(resolve(repository,'artifacts/M9/secret-scan-verification.json'),'utf8'));
 const legacy=retainedM9ScanMaterial(legacyHarness,legacyBrowser,legacyBrowserMaterial,acceptedLegacy,readFileSync(resolve(repository,'tests/security/m9-native-actual.mjs'),'utf8'),environment,{harness,browser,browserMaterial});
 excludedNonCredentialProbes.push({...legacy.evidence,retainedMilestone:'M9',acceptedProvenanceReverified:true});
 check('retained M9 original ledger is unchanged and sole exact probe proof remains exclusive',readFileSync(`${privateDirectory}/m9-harness.json`).equals(legacyLedgerBytes));
 const collected=m10SecretMaterial(harness,browser,environment,browserMaterial,legacy,{proofBytes:readFileSync(resolve(repository,M10_CONTROL_ID_PROOF_PATH)),verifiedBrowserRetention:browserEvidenceRetention});explicitFixtureKeyCount=collected.explicitFixtureKeyCount;controlIdentifierNormalization=collected.controlIdentifierNormalization;
 check('only frozen exact original control metadata occurrences normalize in a collector clone; all actual credential leaves remain scanned');
 const exports=[];for(const packet of collected.material.requests)if(typeof packet.rawResponseText==='string'&&packet.rawResponseText.includes('_format_version:'))exports.push(parse(packet.rawResponseText));
 const combined=new Map();for(const row of [...collected.secrets,...collectSecretMaterial({requests:[]},environment,{exports})]){const prior=combined.get(row.value);combined.set(row.value,{value:row.value,kinds:[...new Set([...(prior?.kinds??[]),...row.kinds])].sort()});}const secrets=[...combined.values()];secretCount=secrets.length;
 check('two actual gateway keys are explicitly scanned',explicitFixtureKeyCount>=2);
 check('actual passwords, API keys, cookies, CSRF and encryption/session environment material included',['password','api-key','cookie','csrf','environment-secret'].every(kind=>secrets.some(row=>row.kinds.includes(kind))));
 const ledgerKeys=new Set(collected.material.requests.map(packet=>packet.key??packet.idempotencyKey).filter(Boolean));check('idempotency identifiers are not credentials',secrets.every(row=>!ledgerKeys.has(row.value)));
 unknownOriginalResponses=collected.material.requests.filter(packet=>['prepared','response_unknown'].includes(packet.state)).length;retainedFailedOriginalRequests=collected.material.requests.filter(packet=>packet.status>=400).length;
 const matcher=buildSecretMatcher(secrets);patternCount=matcher.patternCount;
 const scan=(label,bytes,group)=>{scannedBytes+=bytes.length;if(bytes.length>64*1024*1024||scannedBytes>640*1024*1024)throw Error('PUBLIC_SCAN_BYTE_BUDGET');fileGroups[group]++;for(const finding of matcher.scan(bytes))findings.push({path:matcher.scan(Buffer.from(label)).length?'[PRIVATE_VALUE_IN_PATH]':label,...finding});};
 const git=spawnSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:repository,encoding:'utf8',timeout:10000,maxBuffer:8*1024*1024});if(git.error||git.status!==0)throw Error('PUBLIC_FILE_ENUMERATION_FAILED');
 const files=new Map();for(const name of new Set(git.stdout.split('\0').filter(Boolean)))files.set(resolve(repository,name),{label:name,group:'repository'});
 const walk=(directory,group)=>{if(!existsSync(directory))throw Error('CURRENT_THREE_DIST_BUILDS_REQUIRED');for(const entry of readdirSync(directory,{withFileTypes:true})){const path=resolve(directory,entry.name);if(entry.isDirectory())walk(path,group);else files.set(path,{label:relative(repository,path),group});}};
 for(const[directory,group]of[['apps/console-api/dist','console-api-dist'],['apps/console-web/dist','console-web-dist'],['apps/portal-web/dist','portal-web-dist']])walk(resolve(repository,directory),group);
 if(files.size>15000)throw Error('PUBLIC_SCAN_FILE_BUDGET');for(const[path,descriptor]of files){if(!existsSync(path))continue;const actual=realpathSync(path);if(actual!==repository&&!actual.startsWith(repository+sep))throw Error('EXTERNAL_PUBLIC_SYMLINK_REFUSED');if(lstatSync(actual).isFile())scan(descriptor.label,readFileSync(actual),descriptor.group);}
 check('public repository and all three current builds scanned',Object.values(fileGroups).slice(0,4).every(count=>count>0));
 for(const container of ownedContainers){const name=JSON.parse(docker(['inspect','--format','{{json .Name}}',container]).toString().trim());if(name!==`/${container}`)throw Error('OWNED_CONTAINER_GATE_FAILED');scan(`docker://${container}/logs`,docker(['logs',container]),'owned-container-log');}
 check('all ten own lab stdout and stderr logs scanned without clipping',fileGroups['owned-container-log']===10);
 const auditReader=`const {Client}=require('pg');(async()=>{const u=new URL(process.env.DATABASE_URL);if(process.env.RELEASE_LAB_READY!=='true'||u.hostname!=='console-db'||u.port!=='5432'||u.pathname!=='/kongpilot'||u.username!=='kongpilot_lab_app')throw Error('CONSOLE_DATABASE_GATE');const c=new Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3000});try{await c.connect();await c.query('BEGIN READ ONLY');await c.query("SET LOCAL statement_timeout='10s'");const r=await c.query('SELECT * FROM audit_events WHERE chain_scope=ANY($1::text[]) ORDER BY chain_scope,sequence LIMIT 20001',[${JSON.stringify([...clusterIds.map(id=>`cluster:${id}`),'global'])}]);if(r.rows.length===0||r.rows.length>20000)throw Error('AUDIT_ROW_BUDGET');process.stdout.write(JSON.stringify(r.rows));}finally{await c.query('ROLLBACK').catch(()=>{});await c.end();}})().catch(()=>{process.exitCode=1;});`;
 scan('postgres://own-console/kongpilot/both-clusters-and-global-audit',docker(['exec','-e','RELEASE_LAB_READY=true','kongpilot-release-lab-console-api-1','node','-e',auditReader]),'owned-audit-records');
 check('both actual cluster chains and global audit values scanned only in memory',fileGroups['owned-audit-records']===1);check('zero actual secret literal or common encoded leaks',findings.length===0);passed=true;
}catch(error){failure={code:/^[A-Z0-9_]+$/.test(error?.message??'')?error.message:error?.code==='ERR_ASSERTION'?'ASSERTION_FAILED':'M10_SCAN_FAILED'};}
finally{const report={passed,milestone:'M10',environment:'self-owned RAM release lab with two physical gateways',productionDeployment:false,credentialsRecorded:false,actualSecretCount:secretCount,explicitFixtureKeyCount,patternCount,scannedBytes,fileGroups,checks,findings,unknownOriginalResponses,retainedFailedOriginalRequests,unknownOriginalResponsesResolved:false,excludedNonCredentialProbes,...(controlIdentifierNormalization?{controlIdentifierNormalization}:{}),authenticationJournalCoverage:authenticationJournalCoverage??{validated:false,evidencePath:M10_AUTH_JOURNAL_EVIDENCE_PATH,expectedEvidenceSha256:M10_AUTH_JOURNAL_EVIDENCE_SHA256},...(browserEvidenceRetention?{browserEvidenceRetention}:{}),scanScope:'all public tracked/untracked files, three dist builds, complete ten own container stdout/stderr logs, and both cluster/global actual audit rows',limits:['Byte scanning does not OCR screenshots; separate browser DOM checks must pass.','Coverage is actual retained current/legacy fixture material, not credentials created outside this lab.',M10_AUTH_JOURNAL_LIMITATION],...(failure?{failure}:{})};mkdirSync(dirname(reportPath),{recursive:true});if(existsSync(reportPath)){let suffix=1;while(existsSync(reportPath.replace('.json',`.attempt-${suffix}.json`)))suffix++;writeFileSync(reportPath.replace('.json',`.attempt-${suffix}.json`),readFileSync(reportPath));}writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n');process.stdout.write(JSON.stringify({passed,checks:checks.length,actualSecretCount:secretCount,explicitFixtureKeyCount,patterns:patternCount,files:fileGroups,scannedBytes,findingCount:findings.length,...(failure?{failure}:{})})+'\n');if(!passed)process.exitCode=1;}

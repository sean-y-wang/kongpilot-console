import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {beforeEach,describe,expect,it,vi} from 'vitest';

const state=vi.hoisted(()=>({files:new Map<string,string>(),capture:vi.fn(),assetHash:'a'.repeat(64)}));
vi.mock('node:fs',async()=>{
 const actual=await vi.importActual<typeof import('node:fs')>('node:fs');
 return{...actual,existsSync:(path:any)=>state.files.has(String(path)),mkdirSync:vi.fn(),readFileSync:(path:any,encoding?:any)=>{const text=state.files.get(String(path));if(text===undefined)throw new Error('UNAPPROVED_OFFLINE_READ');return encoding==='utf8'?text:Buffer.from(text);},writeFileSync:(path:any,value:any,options?:any)=>{if(options?.flag==='wx'&&state.files.has(String(path)))throw new Error('OFFLINE_EXCLUSIVE_FILE_EXISTS');state.files.set(String(path),String(value));}};
});
vi.mock('../../../deploy/scripts/verify-failed-issue-repair-continuity.mjs',async()=>({...await vi.importActual<any>('../../../deploy/scripts/verify-failed-issue-repair-continuity.mjs'),captureFailedIssueRepairSnapshot:state.capture}));
vi.mock('../../../deploy/scripts/verify-portal-tenant-static-continuity.mjs',async()=>({...await vi.importActual<any>('../../../deploy/scripts/verify-portal-tenant-static-continuity.mjs'),portalTenantPublicSourceInventory:()=>({'apps/example.ts':hash}),portalTenantAssetManifest:(directory:string)=>({[`${directory}/rebuilt-asset`]:state.assetHash})}));
import {assertUnsealedPortalReadFeaturesRecord,portalReadFeaturesChecks,portalReadFeaturesMain} from '../../../deploy/scripts/verify-portal-read-features-continuity.mjs';

const hash='a'.repeat(64),other='b'.repeat(64),label='portal-catalog-admin-details',gatePath='artifacts/M6/source-portal-read-features-release-gate.json',output=`artifacts/M6/${label}-repair-continuity.json`;
const digest=(value:string)=>createHash('sha256').update(value).digest('hex');
const names=['kong','kong-secondary','kong-db','kong-secondary-db','console-db','redis','telemetry-collector','prometheus','loki','echo-upstream','console-web','portal-web'];
const migrations=Array.from({length:10},(_,i)=>({name:i===9?'009_m6_failed_issue_abandonment.sql':`${String(i).padStart(3,'0')}_test.sql`,checksum:digest(`migration-${i}`)}));
function snapshot():any{return{
 foundation:{core:{services:names.map(name=>({name,id:name,startedAt:'same',image:'same',envSHA256:hash,volumes:[{name:'same',target:'same'}],networks:[{id:'same',ip:'same'}]})),api:{name:'console-api',id:'same',image:'same',envSHA256:hash,networks:[{id:'same',ip:'same'}],volumes:[{name:'same',target:'same'}]},materialSHA256:hash,database:{settings:[{credential_generation:2},{credential_generation:1}],epochIdentitySHA256:hash}},c3:['kong-portal','kong-portal-db','kong-portal-migrations'].map(name=>({name,id:name,startedAt:'same',image:'same',envSHA256:hash,networks:[{id:'same',ip:'same'}],volumes:[{name:'same',target:'same'}],state:name.endsWith('migrations')?'exited':'running',health:name.endsWith('migrations')?null:'healthy',exitCode:0})),privateFiles:{environment:{inode:1,mode:0o600,mtimeMs:1,size:1,sha256:hash},runtimeReference:{inode:2,mode:0o600,mtimeMs:1,size:1,sha256:hash}}},
 sourceMigrations:structuredClone(migrations),migrationService:{id:'original-migrator',startedAt:'same',finishedAt:'same',state:'exited',exitCode:0,envSHA256:hash},
 business:{migrations:migrations.map(row=>({...row,applied_at:'same'})),first:{rowSHA256:hash,keyCipherSHA256:hash},failed:{rowSHA256:hash},managedTotals:{references:{count:8,sha256:hash},grants:{count:6,sha256:hash},credentials:{count:5,sha256:hash},publicationProofs:{count:2,sha256:hash}},abandonmentTable:{certificateCount:1,privileges:{read:true,append:true,update:false}},publicationProofPrivileges:{read:true,append:true,update:false}},publicSources:{'apps/example.ts':hash},assets:{api:{old:hash},console:{old:hash},portal:{old:hash}}
};}
function gate(){return{allPassed:true,label,sourceSha256:{'apps/example.ts':digest('frozen')},migrations:structuredClone(migrations)};}
function installGate(value:any=gate()){state.files.set(gatePath,JSON.stringify(value));}
beforeEach(()=>{state.files.clear();state.capture.mockReset();state.capture.mockImplementation(()=>snapshot());state.assetHash=hash;state.files.set('apps/example.ts','frozen');for(const[index,row]of migrations.entries())state.files.set(resolve('apps/console-api/src/infrastructure/migrations',row.name),`migration-${index}`);installGate();});
const passed=(before:any,after:any)=>portalReadFeaturesChecks(before,after,migrations).every((row:any)=>row.passed);

describe('independent M6 read-feature process-only and three-static-build continuity',()=>{
 it('permits rebuilt API/Console/Portal artifacts and an API-only process restart with all15 other processes and facts retained',()=>{const before=snapshot(),after=structuredClone(before);after.assets={api:{new:other},console:{new:other},portal:{new:other}};expect(passed(before,after)).toBe(true);expect(portalReadFeaturesChecks(before,after,migrations)).toHaveLength(27);});
 it.each(['API-id','API-image','API-env','API-network','API-volume','outside-process','C3-process','C3-bootstrap','private-env','private-ref','metrics-generation','metrics-epoch','migrator','source','refs','proof','credential','certificate','migration-checksum','migration-applied-at'])('rejects unauthorized change %s',kind=>{
  const before=snapshot(),after=structuredClone(before),api=after.foundation.core.api,business=after.business;
  if(kind==='API-id')api.id='new';if(kind==='API-image')api.image='new';if(kind==='API-env')api.envSHA256=other;if(kind==='API-network')api.networks[0].ip='new';if(kind==='API-volume')api.volumes[0].name='new';if(kind==='outside-process')after.foundation.core.services[0].startedAt='new';if(kind==='C3-process')after.foundation.c3[0].startedAt='new';if(kind==='C3-bootstrap')after.foundation.c3[2].state='running';if(kind==='private-env')after.foundation.privateFiles.environment.inode++;if(kind==='private-ref')after.foundation.privateFiles.runtimeReference.sha256=other;if(kind==='metrics-generation')after.foundation.core.database.settings[0].credential_generation++;if(kind==='metrics-epoch')after.foundation.core.database.epochIdentitySHA256=other;if(kind==='migrator')after.migrationService.id='new';if(kind==='source')after.publicSources['apps/example.ts']=other;if(kind==='refs')business.managedTotals.references.sha256=other;if(kind==='proof')business.publicationProofPrivileges.update=true;if(kind==='credential')business.first.keyCipherSHA256=other;if(kind==='certificate')business.abandonmentTable.certificateCount++;if(kind==='migration-checksum')business.migrations[0].checksum=other;if(kind==='migration-applied-at')business.migrations[9].applied_at='new';
  expect(passed(before,after)).toBe(false);
 });
 it('actual main rejects invalid arguments, frozen source and mismatched gate migration checksum before runtime capture',()=>{
  expect(()=>portalReadFeaturesMain(['--restart'])).toThrow();expect(state.capture).not.toHaveBeenCalled();
  state.files.set('apps/example.ts','changed');expect(()=>portalReadFeaturesMain(['--before'])).toThrow();expect(state.capture).not.toHaveBeenCalled();
  state.files.set('apps/example.ts','frozen');const changed=gate();changed.migrations[0].checksum=other;installGate(changed);expect(()=>portalReadFeaturesMain(['--before'])).toThrow();expect(state.capture).not.toHaveBeenCalled();
 });
 it('actual main rejects existing before and sealed after without any Docker/DB/private capture',()=>{
  state.files.set(output,JSON.stringify({stage:'M6',label,allPassed:true,before:snapshot()}));expect(()=>portalReadFeaturesMain(['--before'])).toThrow();expect(()=>portalReadFeaturesMain(['--after'])).toThrow();expect(state.capture).not.toHaveBeenCalled();
 });
 it('actual main compares saved gate SHA before fresh-after capture, even if new gate has valid source/migration values',()=>{
  const initial=state.files.get(gatePath)!;state.files.set(output,JSON.stringify({stage:'M6',label,sourceReleaseSHA256:digest(initial),allPassed:null,before:snapshot()}));installGate({...gate(),extraApproval:'different-gate'});expect(()=>portalReadFeaturesMain(['--after'])).toThrow();expect(state.capture).not.toHaveBeenCalled();
 });
 it('actual main passes the tested historical-subject readonly program and seals success only once while allowing all3 rebuilt manifests',()=>{
  portalReadFeaturesMain(['--before']);expect(state.capture).toHaveBeenCalledTimes(1);const readonly=state.capture.mock.calls[0][1];expect(readonly).toContain('origin.subject_id=g.id');expect(readonly).toContain('origin.cluster_id=g.cluster_id AND origin.workspace_id=g.workspace_id');expect(readonly).toContain('REPEATABLE READ READ ONLY');expect(readonly).not.toContain('FROM portal_application_grants g WHERE g.workflow_id=$1');
  state.assetHash=other;portalReadFeaturesMain(['--after']);const saved=JSON.parse(state.files.get(output)!);expect(saved.allPassed).toBe(true);expect(saved.before.assets.api).not.toEqual(saved.after.assets.api);expect(saved.before.assets.console).not.toEqual(saved.after.assets.console);expect(saved.before.assets.portal).not.toEqual(saved.after.assets.portal);expect(()=>portalReadFeaturesMain(['--after'])).toThrow();expect(state.capture).toHaveBeenCalledTimes(2);
 });
 it('retains failed continuity output and refuses correction over a sealed failed record',()=>{
  portalReadFeaturesMain(['--before']);state.capture.mockImplementation(()=>{const value=snapshot();value.business.managedTotals.references.sha256=other;return value;});const originalExitCode=process.exitCode;try{portalReadFeaturesMain(['--after']);expect(JSON.parse(state.files.get(output)!).allPassed).toBe(false);const preserved=state.files.get(output);expect(()=>portalReadFeaturesMain(['--after'])).toThrow();expect(state.files.get(output)).toBe(preserved);expect(state.capture).toHaveBeenCalledTimes(2);}finally{process.exitCode=originalExitCode;}
 });
 it.each([{stage:'M5',label,allPassed:null,before:{}},{stage:'M6',label:'foreign',allPassed:null,before:{}},{stage:'M6',label,allPassed:false,before:{}},{stage:'M6',label,allPassed:null,before:{},after:{}},{stage:'M6',label,allPassed:null,before:{},checks:[]}])('rejects sealed or foreign record shape without runtime calls',value=>expect(()=>assertUnsealedPortalReadFeaturesRecord(value)).toThrow());
 it('deployment plan orders only three workspace builds, one console-api restart and verify-only within exact7 steps',async()=>{
  const fs=await vi.importActual<typeof import('node:fs')>('node:fs'),plan=fs.readFileSync('docs/milestones/M6-portal-read-features-deployment-plan.md','utf8'),steps=plan.split('\n').filter(line=>/^\d\. /.test(line));
  expect(steps).toHaveLength(7);expect(steps[0]).toContain('--before');expect(steps[1]).toContain('npm run build -w @kongpilot/api');expect(steps[2]).toContain('npm run build -w @kongpilot/web');expect(steps[3]).toContain('npm run build -w @kongpilot/portal-web');expect(steps[4]).toContain('restart console-api');expect(steps[5]).toContain('--verify-only');expect(steps[6]).toContain('--after');expect(steps.join('\n')).not.toMatch(/docker compose up|--force-recreate|console-migrations|npm run build`|enroll|rotate/);
 });
});

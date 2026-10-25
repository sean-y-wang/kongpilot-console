import{verifyProductionAuditChain}from'./lib/production-audit-integrity.mjs';
import{readFileSync,existsSync}from'node:fs';import{execFileSync}from'node:child_process';import{ProductionHarness}from'./lib/production-http-harness.mjs';import{productionSixCredentials}from'./lib/production-proxy.mjs';import{durableProductionJson}from'./lib/production-ui-storage.mjs';
const out='artifacts/Production/root-production-restored-decryption-six-credentials-actual.json';if(existsSync(out)||process.env.PRODUCTION_RESTORE_CREDENTIALS_EXCLUSIVE_READY!=='true')throw Error('PRODUCTION_RESTORE_VERIFY_EXCLUSIVE_REQUIRED');
const restore=JSON.parse(readFileSync('artifacts/Production/root-production-third-project-restore-actual.json'));if(!restore.allPassed||restore.project!=='kongos-restore-m08-20261012-a3'||!restore.oldSessionsFencedBeforeApiOpen)throw Error('PRODUCTION_ORIGINAL_RESTORE_CHECKPOINT_REQUIRED');
const h=new ProductionHarness({resume:true});h.state.restoreTargetVerified=true;h.save();const base=h.request.bind(h);h.request=(s,p,m,b,options={})=>base(s,p,m,b,{...options,originOverride:'https://localhost:21443'});
const old=h.state.sessions.bootstrap;await h.request(old,'/api/v1/auth/me','GET',undefined,{expected:[401]});
const env=Object.fromEntries(readFileSync('/dev/shm/kongos-production-ram-m08-20261012-a3/private/production/.env','utf8').split('\n').filter(l=>l.includes('=')).map(l=>{const i=l.indexOf('=');return[l.slice(0,i),l.slice(i+1)]}));
const actor=await h.login('restored-admin',env.BOOTSTRAP_ADMIN_USERNAME,env.BOOTSTRAP_ADMIN_PASSWORD),area=h.state.scope;
const snapshot=(await h.request(actor,`/api/v1/clusters/${area.cid}/snapshots/${h.state.productionSnapshot.snapshotId}?workspaceId=${area.wid}&size=20`)).data;
if(snapshot.entity?.id!==h.state.productionSnapshot.snapshotId||snapshot.entity?.completeness!=='complete')throw Error('RESTORED_SEALED_SNAPSHOT_NOT_COMPLETE');
const key=Object.values(h.state.nativeFixture.plugins).find(p=>p.name==='oauth2');
const secret=(await h.request(actor,`/api/v1/clusters/${area.cid}/entities/plugins/${key.id}?workspaceId=${area.wid}&reveal=true`)).data.entity;
if(secret.config.provision_key!==h.state.nativeFixture.provisionKey)throw Error('RESTORED_ORIGINAL_ENCRYPTED_PLUGIN_MATERIAL_NOT_DECRYPTED');
// Independent, isolated echo fixture on the third project's proxy network.
execFileSync('docker',['--host=unix:///dev/shm/kongos-production-ram-m08-20261012-a3/run/docker-production.sock','network','connect','--alias','echo-upstream','kongos-restore-m08-20261012-a3_proxy-edge','kongos-production-echo-m08-20261012-a3'],{stdio:['ignore','pipe','pipe']});
await productionSixCredentials(h,h.state.nativeFixture,'third-project-restored-original-credentials',true);
const integrity=await verifyProductionAuditChain(h,actor,area.cid);
h.state.productionRestoreCredentialsComplete=true;h.save();const result={performedAt:new Date().toISOString(),allPassed:true,restoredProject:restore.project,originalAuditCheckpointPreserved:true,oldSignedSessionDenied:true,originalEncryptedPluginSecretDecrypted:true,originalCompleteSnapshotReadable:true,credentialKinds:6,credentialStages:h.state.credentialStages.at(-1),auditIntegrity:integrity,restoreElapsedSeconds:restore.restoreElapsedSeconds,privateSecretsPublished:false,offHostStorageTested:false};durableProductionJson(out,result,true,0o644);console.log(JSON.stringify({allPassed:true,actualRestoredCredentialKinds:6,originalSecretsDecrypted:true,oldSessionDenied:true}));

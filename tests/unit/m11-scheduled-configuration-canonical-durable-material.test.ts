import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { configurationJobSubjectMaterial } from '../../apps/console-api/src/modules/workflows/workflow-configuration-job-subject';
import { durableConfigurationLocator } from '../../apps/console-api/src/modules/configuration/configuration-durable.codec';
import { longConfigurationMaterialFixture } from './helpers/m11-long-configuration-material-fixture';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','94'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('scheduled Origin agrees with the authoring canonical durable material',()=>{
 it('preserves the exact legacy seal with migration038 NULL/default domain columns and pre038 absent keys',async()=>{
  const f=await longConfigurationMaterialFixture(false),business=await f.readBusiness(),origin=await f.readOrigin();expect(origin).toEqual(business);
  const legacy=configurationJobSubjectMaterial(f.job);expect(legacy).not.toHaveProperty('authorityDomain');expect(legacy).not.toHaveProperty('durableIssueId');
  const absent={...f.job};delete absent.authority_domain;delete absent.durable_issue_id;expect(f.secrets.fingerprint(configurationJobSubjectMaterial(absent))).toBe(f.secrets.fingerprint(legacy));
  expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('keeps the authoring seal unchanged after twenty minutes while decrypting and verifying the actual durable AEAD envelope',async()=>{
  const f=await longConfigurationMaterialFixture(),frozen=JSON.stringify(f.rows),business=await f.readBusiness(),origin=await f.readOrigin();
  expect(Date.now()-Date.parse(f.job.created_at)).toBeGreaterThan(15*60_000);expect(Date.parse(f.envelope.admissionExpiresAt)).toBeLessThan(Date.now());
  expect(origin).toEqual(business);expect(origin.subjectSeal).toEqual(business.subjectSeal);expect(origin.plan).toEqual(f.plan);
  expect(configurationJobSubjectMaterial(f.job)).toMatchObject({authorityDomain:'durable-configuration-v1',durableIssueId:f.ids.issue});
  expect(f.db.one.mock.calls.some(([sql])=>sql.includes('FROM configuration_durable_issues'))).toBe(true);
  expect(f.db.one.mock.calls.some(([sql])=>sql.includes('FROM configuration_durable_bindings'))).toBe(true);
  expect(JSON.stringify(f.rows)).toBe(frozen);expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['missing-issue','missing-binding','forged-owner','forged-workflow','ciphertext','material-hmac','foreign-aad','policy','baseline']as const)('rejects %s in the real durable repository before returning scheduled subject material',async mode=>{
  const f=await longConfigurationMaterialFixture();
  if(mode==='missing-issue')f.rows.issue=null;if(mode==='missing-binding')f.rows.binding=null;if(mode==='forged-owner')f.rows.issue.owner_id=randomUUID();if(mode==='forged-workflow')f.rows.binding.workflow_id=randomUUID();
  if(mode==='ciphertext')f.rows.binding.envelope_ciphertext=f.rows.binding.envelope_ciphertext.slice(0,-3)+'xyz';if(mode==='material-hmac')f.rows.binding.material_hmac='0'.repeat(64);
  if(mode==='foreign-aad'){const foreign={...f.envelope,jobId:randomUUID()};f.rows.binding.envelope_ciphertext=f.codec.seal(foreign,durableConfigurationLocator(foreign),Date.parse(foreign.issuedAt)).ciphertext;}
  if(mode==='policy')f.rows.policy.policy={...f.rows.policy.policy,intentTtlHours:48};if(mode==='baseline')f.rows.baseline.material_state='destroyed';
  await expect(f.readOrigin()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_BINDING_INVALID'}});expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['unknown-domain','partial-domain','partial-issue','different-issue']as const)('rejects marked job %s without falling back to legacy material',async mode=>{
  const f=await longConfigurationMaterialFixture();if(mode==='unknown-domain')f.job.authority_domain='durable-configuration-v2';if(mode==='partial-domain')f.job.authority_domain=null;
  if(mode==='partial-issue')f.job.durable_issue_id=null;if(mode==='different-issue')f.job.durable_issue_id=randomUUID();
  await expect(f.readOrigin()).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('rejects a durable planRef inside an unmarked legacy job and a marked job without that authenticated planRef',async()=>{
  const legacy=await longConfigurationMaterialFixture(false,{legacyPlanRef:true});await expect(legacy.readOrigin()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_BINDING_INVALID'}});
  const absent=await longConfigurationMaterialFixture(true,{omitPlanRef:true});await expect(absent.readOrigin()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_BINDING_INVALID'}});
 });
 it('commits the durable domain and original issue ID into immutable subject bytes without broadening the old legacy domain',async()=>{
  const f=await longConfigurationMaterialFixture(),canonical=configurationJobSubjectMaterial(f.job);
  for(const change of [{authority_domain:'unknown'}, {durable_issue_id:randomUUID()}])expect(f.secrets.fingerprint(configurationJobSubjectMaterial({...f.job,...change}))).not.toBe(f.secrets.fingerprint(canonical));
  const mutable={...f.job,state:'running',revision:99,lease_generation:77,updated_at:new Date().toISOString()};expect(configurationJobSubjectMaterial(mutable)).toEqual(canonical);
 });
});

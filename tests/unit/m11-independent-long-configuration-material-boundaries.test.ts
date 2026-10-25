import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { durableConfigurationLocator } from '../../apps/console-api/src/modules/configuration/configuration-durable.codec';
import { longConfigurationMaterialFixture } from './helpers/m11-long-configuration-material-fixture';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','94'.repeat(32)));
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
const denyBoth=async(f:Awaited<ReturnType<typeof longConfigurationMaterialFixture>>)=>{
 await expect(f.readBusiness()).rejects.toThrow();await expect(f.readOrigin()).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
};
describe('independent original durable material lifecycle and cryptographic boundaries',()=>{
 it('accepts admission-expired but original business-unexpired material without renewing either timestamp',async()=>{
  const f=await longConfigurationMaterialFixture(),original=JSON.stringify(f.rows);
  expect(Date.parse(f.envelope.admissionExpiresAt)).toBeLessThan(Date.now());
  const b=await f.readBusiness(),o=await f.readOrigin();expect(b.subjectSeal).toEqual(o.subjectSeal);
  expect(o.job.authority_expires_at).toBe(f.envelope.expiresAt);expect(o.job.expires_at).toBe(f.envelope.expiresAt);
  expect(JSON.stringify(f.rows)).toBe(original);expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('rejects at the exact original expiry instead of manufacturing a new authoring horizon',async()=>{
  const f=await longConfigurationMaterialFixture();vi.spyOn(Date,'now').mockReturnValue(Date.parse(f.envelope.expiresAt));await denyBoth(f);
 });
 it('rejects a future-issued envelope before its original issue time',async()=>{
  const f=await longConfigurationMaterialFixture();vi.spyOn(Date,'now').mockReturnValue(Date.parse(f.envelope.issuedAt)-1);await denyBoth(f);
 });
 it.each(['authority','job','session','credential','permission','cluster-revision','workspace-revision'] as const)('rejects changed immutable %s facts without adopting the new value',async mode=>{
  const f=await longConfigurationMaterialFixture();
  if(mode==='authority')f.job.authority_expires_at=new Date(Date.parse(f.envelope.expiresAt)+1).toISOString();
  if(mode==='job')f.job.expires_at=new Date(Date.parse(f.envelope.expiresAt)+1).toISOString();
  if(mode==='session')f.job.origin_session_id=randomUUID();
  if(mode==='credential')f.job.credential_epoch=2;
  if(mode==='permission')f.job.permission_version=`${f.ids.actor}:2:1`;
  if(mode==='cluster-revision')f.job.cluster_revision=2;
  if(mode==='workspace-revision')f.job.workspace_revision=2;
  await denyBoth(f);
 });
 it('rejects valid ciphertext and valid HMAC sealed under a foreign same-plan workspace AAD',async()=>{
  const f=await longConfigurationMaterialFixture(),foreign={...f.envelope,workspaceId:randomUUID()};
  const sealed=f.codec.seal(foreign,durableConfigurationLocator(foreign),Date.parse(foreign.issuedAt));
  f.rows.binding.envelope_ciphertext=sealed.ciphertext;f.rows.binding.material_hmac=sealed.materialHmac;await denyBoth(f);
 });
 it.each(['manifest','wrapped-key','step'] as const)('retains real Snapshot AES-GCM authentication for %s alongside durable authentication',async part=>{
  const f=await longConfigurationMaterialFixture();
  if(part==='manifest')f.rows.version.manifest_ciphertext=f.rows.version.manifest_ciphertext.slice(0,-1)+'!';
  if(part==='wrapped-key')f.rows.material.wrapped_key_secret=f.rows.material.wrapped_key_secret.slice(0,-1)+'!';
  if(part==='step')f.objects[0].payload_ciphertext=f.objects[0].payload_ciphertext.slice(0,-1)+'!';
  await denyBoth(f);
 });
});

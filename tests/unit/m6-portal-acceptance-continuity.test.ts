import { describe, expect, it } from 'vitest';
import { portalAcceptanceContinuityChecks } from '../../deploy/scripts/verify-portal-acceptance-continuity.mjs';

function pair(): any {
  const before = { core: {services:[{name:'portal-web',id:'portal',startedAt:'unchanged',envSHA256:'same'}],api:{id:'old-api',image:'same',envSHA256:'old-full-env',networks:[{name:'project_frontend',id:'old-network',ip:'172.23.0.3'}],volumes:[]},materialSHA256:'same-material',database:{generations:[2,1],epochSHA256:'same'}},policy:{stableEnvSHA256:'same-credentials',allowRules:['kong','kong-secondary'],protectedHosts:['portal-web','172.28.42.20','telemetry-collector']},reference:{inode:3,mode:384,mtimeMs:1,size:1000,sha256:'same-private-reference'}};
  const after = structuredClone(before);
  after.core.api.id='new-api';after.core.api.envSHA256='required-extended-env';after.core.api.networks.push({name:'project_kong-portal-admin',id:'new-network',ip:'172.28.13.10'});
  after.policy.allowRules.push('kong-portal-admin-endpoint:8001');after.policy.protectedHosts.push('kong-portal-db','172.28.23.20','kong-portal-admin-endpoint','172.28.13.20','172.28.13.10');
  return {before,after};
}
const passed = (value: any) => portalAcceptanceContinuityChecks(value.before,value.after).every((row:any)=>row.passed);
describe('M6 isolated C3 minimum API topology transition continuity',()=>{
  it('accepts only explicit API recreate and the one new Admin interface plus exact two env extensions',()=>expect(passed(pair())).toBe(true));
  it.each(['credentials','original-interface','image','old-protection','wildcard','unexpected-interface','wrong-source','old-process','material','generation','epoch','reference-bytes','reference-inode'])('rejects unexpected %s change',kind=>{
    const value=pair(),after=value.after;
    if(kind==='credentials')after.policy.stableEnvSHA256='different';if(kind==='original-interface')after.core.api.networks[0].ip='172.23.0.100';if(kind==='image')after.core.api.image='different';
    if(kind==='old-protection')after.policy.protectedHosts.shift();if(kind==='wildcard')after.policy.allowRules.push('*');if(kind==='unexpected-interface')after.core.api.networks.push({name:'kong-storage',ip:'172.28.23.99'});if(kind==='wrong-source')after.core.api.networks[1].ip='172.28.13.11';
    if(kind==='old-process')after.core.services[0].startedAt='restarted';if(kind==='material')after.core.materialSHA256='different';if(kind==='generation')after.core.database.generations[0]++;if(kind==='epoch')after.core.database.epochSHA256='different';if(kind==='reference-bytes')after.reference.sha256='different';if(kind==='reference-inode')after.reference.inode++;
    expect(passed(value)).toBe(false);
  });
  it.each(['kong-portal-db','172.28.23.20','kong-portal-admin-endpoint','172.28.13.20','172.28.13.10'])('requires new literal/host protection %s independently',host=>{const value=pair();value.after.policy.protectedHosts=value.after.policy.protectedHosts.filter((row:string)=>row!==host);expect(passed(value)).toBe(false);});
});

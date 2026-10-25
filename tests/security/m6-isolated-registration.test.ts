import {describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {registerIsolatedCluster} from './lib/m6-isolated-transition.mjs';

function harness(failure?:'registration'|'probe'){
  const h:any={referenceData:{consoleAdministrator:{user:{id:randomUUID()}}},saved:[],requireLive:vi.fn(),ok:(value:any)=>value,saveReference(value:any){this.referenceData={...this.referenceData,...value};this.saved.push(structuredClone(this.referenceData));}};
  const id=randomUUID();
  h.request=vi.fn(async(_actor:any,path:string,method:string,_body:any,options:any)=>{
    expect(method).toBe('POST');
    const current=h.referenceData.isolatedRegistration;
    if(path==='/clusters'){
      expect(current.key).toBe(options.key);expect(current.state).toBe('before-single-registration');
      if(failure==='registration')throw new Error('synthetic lost registration response');
      return{id,version:null};
    }
    expect(path).toBe(`/clusters/${id}/probe`);expect(current.probe.key).toBe(options.key);expect(current.probe.state).toBe('before-single-probe');
    if(failure==='probe')throw new Error('synthetic lost probe response');
    return{version:'1.5.1'};
  });
  return h;
}
describe('M6 actual registry create contract in isolated harness (offline)',()=>{
  it('persists separate original keys before exactly one registration and one explicit probe, accepting create.version=null',async()=>{const h=harness();const cluster=await registerIsolatedCluster(h,'m6-isolated-unit');expect(cluster.version).toBeNull();expect(h.request).toHaveBeenCalledTimes(2);expect(h.referenceData.isolatedRegistration.probe.state).toBe('response-observed');expect(h.referenceData.isolatedRegistration.key).not.toBe(h.referenceData.isolatedRegistration.probe.key);expect(h.request.mock.calls[0][3].admin_url).toBe('http://kong-portal-admin-endpoint:8001');});
  it('does not send a probe or replace the original key after an unknown registration response',async()=>{const h=harness('registration');await expect(registerIsolatedCluster(h,'m6-isolated-unit')).rejects.toThrow('lost registration');const key=h.referenceData.isolatedRegistration.key;await expect(registerIsolatedCluster(h,'m6-isolated-unit')).rejects.toThrow('already attempted');expect(h.request).toHaveBeenCalledTimes(1);expect(h.referenceData.isolatedRegistration.key).toBe(key);expect(h.referenceData.isolatedRegistration.probe).toBeUndefined();});
  it('retains registered CID and probe key after an unknown probe, with no automatic probe replay',async()=>{const h=harness('probe');await expect(registerIsolatedCluster(h,'m6-isolated-unit')).rejects.toThrow('lost probe');const original=structuredClone(h.referenceData.isolatedRegistration);await expect(registerIsolatedCluster(h,'m6-isolated-unit')).rejects.toThrow('already attempted');expect(h.request).toHaveBeenCalledTimes(2);expect(h.referenceData.isolatedRegistration).toEqual(original);expect(original.probe.state).toBe('before-single-probe');});
  it('rejects a reused isolated checkpoint or non-test tag before the first request',async()=>{const h=harness();await expect(registerIsolatedCluster(h,'old-tag')).rejects.toThrow();h.referenceData.isolatedStart={previousCheckpointSha256:'proof'};await expect(registerIsolatedCluster(h,'m6-isolated-unit')).rejects.toThrow();expect(h.request).not.toHaveBeenCalled();});
});

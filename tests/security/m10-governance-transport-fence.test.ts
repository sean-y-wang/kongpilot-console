import 'reflect-metadata';
import {beforeEach,afterEach,it,expect,vi,describe} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {KongExecutionContextService,GovernanceReadProof} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {KongService} from '../../apps/console-api/src/infrastructure/kong/kong.service';
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn()}));
const transport=vi.mocked(outboundJson),cid='cdc22f3e-5e48-4fa6-9ed9-08d7f16d8d03',wid='850e9914-eef8-4c6e-b2bf-9c8c57168203',uid='f1f76319-2035-4b19-8a07-ffba6f9af4e0',sid='2a61f8e7-70ed-4fc1-a5f8-363125a6c820';
// Actual KongService/ALS/tickets and its rate/DNS/retry boundary. Synthetic
// private policy here isolates transport fencing; live SQL authority is
// independently tested by m10-governance-inventory-authority.test.ts.
describe('M10 governance GET transport before-send fences',()=>{
  let execution:KongExecutionContextService,kong:KongService,redis:any,cluster:any,live:boolean,wire:number,handle:object,proof:GovernanceReadProof;
  beforeEach(()=>{
    vi.stubEnv('KONG_RATE_WAIT_MS','0');execution=new KongExecutionContextService();live=true;wire=0;handle=Object.freeze({});
    cluster={id:cid,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'direct',connection_secret:null,status:'healthy',revision:1};
    proof={actor:{id:uid,username:'synthetic-transport-owner',superAdmin:false},sessionId:sid,clusterId:cid,workspaceId:wid,transportScope:transportScopeFor(cluster.admin_url),module:'governance',permissionVersion:'epoch1',credentialEpoch:1,expiresAt:Date.now()+60000,origin:'http',projection:false,kind:'workspace',rootIds:[]};
    const verify=async(candidate:object)=>{if(candidate!==handle||!live)throw new ForbiddenException({code:'GOVERNANCE_PERMISSIONS_CHANGED'});return proof;};
    execution.installGovernanceReadPolicy({verifyHandle:verify,startRead:async candidate=>({proof:await verify(candidate),limits:{maxCalls:500,maxPages:100,maxRecords:10000,maxBytes:33554432,timeoutMs:60000}}),endRead:()=>{},filterResponse:async(_handle,_path,result)=>result});
    execution.installPolicy({authorizeRequest:async(frame,cluster,method,path,body,query)=>{await execution.assertGovernanceRequest(frame,cluster,method,path,body,query);return{};},authorizeResponse:async(_ticket,result)=>result});
    redis={rateLimit:vi.fn(async()=>({allowed:true})),withLock:vi.fn((_name:any,fn:any)=>fn()),assertLeaseOwnership:vi.fn(),assertLeaseActive:vi.fn()};
    kong=new KongService({one:vi.fn(async()=>cluster)} as any,redis,{decrypt:()=>null,redactError:(value:any)=>value} as any,{} as any,execution);
    transport.mockReset();transport.mockImplementation(async(_base,_path,_method,_body,_query,_auth,_timeout,syncFence,afterDns)=>{await afterDns?.();syncFence?.();wire++;return{status:200,body:{version:'1.5.1'}};});
  });
  afterEach(()=>vi.unstubAllEnvs());
  it('rate-slot await revocation prevents entering outbound transport',async()=>{
    redis.rateLimit.mockImplementation(async()=>{live=false;return{allowed:true};});await expect(execution.runGovernanceRead(handle,()=>kong.request(cid,'GET','/'))).rejects.toMatchObject({response:{code:'GOVERNANCE_PERMISSIONS_CHANGED'}});
    expect(transport).not.toHaveBeenCalled();expect(wire).toBe(0);
  });
  it('revocation while DNS is resolving prevents the first HTTP bytes',async()=>{
    transport.mockImplementation(async(_base,_path,_method,_body,_query,_auth,_timeout,syncFence,afterDns)=>{live=false;await afterDns?.();syncFence?.();wire++;return{status:200,body:{}};});
    await expect(execution.runGovernanceRead(handle,()=>kong.request(cid,'GET','/'))).rejects.toMatchObject({response:{code:'GOVERNANCE_PERMISSIONS_CHANGED'}});expect(transport).toHaveBeenCalledTimes(1);expect(wire).toBe(0);
  });
  it('actual physical scope change at the DNS fence blocks the original destination',async()=>{
    transport.mockImplementation(async(_base,_path,_method,_body,_query,_auth,_timeout,syncFence,afterDns)=>{proof={...proof,transportScope:transportScopeFor('http://other-kong:8001')};await afterDns?.();syncFence?.();wire++;return{status:200,body:{}};});
    await expect(execution.runGovernanceRead(handle,()=>kong.request(cid,'GET','/'))).rejects.toMatchObject({response:{code:'GOVERNANCE_READ_CHANGED'}});expect(wire).toBe(0);
  });
  it('revocation following GET 503 allows no retry packet',async()=>{
    transport.mockImplementation(async(_base,_path,_method,_body,_query,_auth,_timeout,syncFence,afterDns)=>{await afterDns?.();syncFence?.();wire++;live=false;return{status:503,body:{}};});
    await expect(execution.runGovernanceRead(handle,()=>kong.request(cid,'GET','/'))).rejects.toMatchObject({response:{code:'GOVERNANCE_PERMISSIONS_CHANGED'}});expect(wire).toBe(1);expect(transport).toHaveBeenCalledTimes(1);
  });
  it('a forged serialized origin never reaches a rate slot or transport',async()=>{
    await expect(execution.runGovernanceRead({...handle},()=>kong.request(cid,'GET','/'))).rejects.toBeInstanceOf(ForbiddenException);expect(redis.rateLimit).not.toHaveBeenCalled();expect(wire).toBe(0);
  });
  it('valid readonly source still observes the normal native GET response',async()=>{
    await expect(execution.runGovernanceRead(handle,()=>kong.request(cid,'GET','/'))).resolves.toEqual({version:'1.5.1'});expect(wire).toBe(1);expect(redis.withLock).not.toHaveBeenCalled();
  });
});

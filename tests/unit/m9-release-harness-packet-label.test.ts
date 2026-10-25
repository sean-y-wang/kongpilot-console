import { describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { ReleaseHarness } from '../security/lib/release-harness.mjs';
const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
describe('M9 real release journal binds fixture labels to the original operation packet',()=>{
  it('keeps an automatic auth refresh distinct from the subsequent approved operation',async()=>{
    const h:any=Object.create(ReleaseHarness.prototype),actorId=randomUUID(),key=randomUUID(),requestId=randomUUID(),body={confirmed:true},path='/clusters/synthetic/workflows/synthetic/approve';
    h.state={requests:[]};h.save=vi.fn();h.request=vi.fn(async(session:any,actualPath:string,method:string,payload:any,options:any)=>{
      h.state.requests.push({key:randomUUID(),path:'/auth/refresh',method:'POST',actorId,bodyHash:hash('null'),state:'response_observed',status:201,requestId:randomUUID()});
      h.state.requests.push({key:options.key,path:actualPath,method,actorId:session.user.id,bodyHash:hash(JSON.stringify(payload)),state:'response_observed',status:201,requestId});
      return{status:201,requestId,data:{approved:true}};
    });
    const response=await h.once('independent-approval',{user:{id:actorId}},path,'POST',body,{key});
    expect(response.data.approved).toBe(true);expect(h.state.requests[0]).not.toHaveProperty('label');expect(h.state.requests[1].label).toBe('independent-approval');
    await h.once('independent-approval',{user:{id:actorId}},path,'POST',body,{key});expect(h.request).toHaveBeenCalledTimes(1);
  });
  it('does not invent completion when the observed response cannot be bound to its original key',async()=>{
    const h:any=Object.create(ReleaseHarness.prototype),actorId=randomUUID(),requestId=randomUUID();h.state={requests:[]};h.save=vi.fn();
    h.request=vi.fn(async()=>{h.state.requests.push({key:randomUUID(),path:'/auth/refresh',method:'POST',actorId,bodyHash:hash('null'),state:'response_observed',status:201,requestId});return{status:201,requestId};});
    await expect(h.once('missing-native-packet',{user:{id:actorId}},'/synthetic/native','POST',{})).rejects.toThrow('The original operation packet');expect(h.state.requests[0]).not.toHaveProperty('label');expect(h.save).not.toHaveBeenCalled();
  });
});

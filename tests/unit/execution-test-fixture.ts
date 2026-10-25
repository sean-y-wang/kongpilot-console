/** Explicit domain-test bridge only; native security tests instantiate the real private context. */
export function executionFixture():any {
 let operation:any;
 return {
  peek:()=>null,current:()=>({operation}),
  runSystemRead:async(_cid:any,_purpose:any,fn:any)=>fn(),runActor:async(_scope:any,fn:any)=>fn(),runMutationActor:async(_scope:any,fn:any)=>fn(),runInternalRead:async(_cid:any,_purpose:any,fn:any)=>fn(),
  runArchiveDelete:async(_scope:any,fn:any)=>fn(),
  approvedMutationBinding:async()=>null,
  bindApprovedOperation:async()=>{throw new Error('Legacy domain fixture cannot authorize approved operations');},
  assertApprovedOperation:async()=>undefined,assertApprovedNativeRequest:async()=>undefined,
  runOperation:async(scope:any,fn:any)=>{const outer=operation;operation=scope;try{return await fn();}finally{operation=outer;}},
 };
}

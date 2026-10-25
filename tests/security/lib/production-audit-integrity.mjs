export async function verifyProductionAuditChain(h,actor,cid){
 const pages=[];let cursor;const endpoint=cid?`/api/v1/clusters/${cid}/audit/integrity`:'/api/v1/audit/global/integrity';
 for(let i=0;i<20;i++){
  const result=await h.request(actor,`${endpoint}${cursor?'?cursor='+encodeURIComponent(cursor):''}`),v=result.data;
  pages.push({...v,actualReadRequestId:result.requestId});
  if(v.status==='verified'&&v.complete===true)return{allPassed:true,pages,checkedRows:pages.reduce((n,p)=>n+p.checkedRows,0),complete:true};
  if(v.status!=='partial'||typeof v.nextCursor!=='string'||v.nextCursor===cursor)throw Error('PRODUCTION_ACTUAL_AUDIT_CHAIN_NOT_VERIFIED');
  cursor=v.nextCursor;
 }
 throw Error('PRODUCTION_AUDIT_CHAIN_PAGE_BUDGET');
}

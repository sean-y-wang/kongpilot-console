import {useEffect,useRef,useState} from 'react';
import {Alert,App,Button,Card,Descriptions,Form,Input,Space,Table,Tag,Typography} from 'antd';
import { abbreviateId, entityOptionLabel } from '../lib/abbreviate-id';
import {useQuery} from '@tanstack/react-query';
import type {User} from '../api/types';
import type {Workflow} from '../features/portal.types';
import {getApiActorId} from '../api/client';
import {newIdempotencyKey} from '../api/idempotency';
import {CursorPagination,useCursorPages} from '../components/CursorPagination';
import {QueryError,formatTime} from '../components/Shared';
import {mutationConfirm} from '../components/MutationConfirm';
import {businessAuthorBody,businessCanAuthor,businessCanCommand,businessCommandBody,businessDeadlineLocalMax,businessReceiptMatches,businessScheduleKinds,businessScheduleLabels,businessWholeWorkspace,
 clearBusinessAttempt,normalizeBusinessSchedule,readBusinessAttempt,sameBusinessIdentity,storeBusinessAttempt,validBusinessIdentity,type BusinessSchedule,type BusinessScheduleAttempt,type BusinessScheduleIdentity,type BusinessScheduleSpec} from '../api/workflow-business-schedules.model';
import {fetchBusinessSchedule,fetchBusinessSchedulePage,fetchBusinessScheduleReceipt,fetchBusinessWorkflow,freshBusinessSession,postBusinessScheduleOnce} from '../api/workflow-business-schedules';

export interface WorkflowBusinessSchedulesPanelProps {clusterId:string;workspaceId:string;actor:User;workflowDetail?:Workflow;readonly?:boolean;onChanged?:()=>void|Promise<unknown>;}
/** Mount as a tab, or pass the currently selected real workflow detail to
 * enable authoring. This component never submits an owner or executor ID. */
export function WorkflowBusinessSchedulesPanel(props:WorkflowBusinessSchedulesPanelProps){
 const {modal,message}=App.useApp(),identity:BusinessScheduleIdentity={actor:props.actor.id,cid:props.clusterId,wid:props.workspaceId,version:props.actor.permissionsVersion??''};
 const scopeKey=JSON.stringify(identity),ready=validBusinessIdentity(identity),pages=useCursorPages(scopeKey);
 const [busy,setBusy]=useState(false),[error,setError]=useState<unknown>(),[journalVersion,setJournalVersion]=useState(0),[form]=Form.useForm<{notBefore:string;windowStart:string;windowEnd:string}>();
 const live=useRef({identity,readonly:props.readonly===true,mounted:true,workflow:props.workflowDetail});live.current={...live.current,identity,readonly:props.readonly===true,workflow:props.workflowDetail};
 useEffect(()=>{live.current.mounted=true;return()=>{live.current.mounted=false;};},[]);
 useEffect(()=>{form.resetFields();setError(undefined);},[scopeKey,props.workflowDetail?.id,props.workflowDetail?.planRevision,form]);
 let attempt:BusinessScheduleAttempt|undefined,journalError:unknown;
 if(ready)try{attempt=readBusinessAttempt(identity);}catch(cause){journalError=cause;}
 // The explicit version re-renders after durable journal writes and clearing.
 void journalVersion;
 const blocked=busy||!!attempt||!!journalError||props.readonly===true;
 const deadlineMax=props.workflowDetail?businessDeadlineLocalMax(props.workflowDetail.expiresAt):undefined;
 const query=useQuery({queryKey:['business-workflow-schedules',identity.actor,identity.cid,identity.wid,identity.version,pages.cursor],
  queryFn:({signal})=>fetchBusinessSchedulePage(identity,pages.cursor,signal),enabled:ready,retry:false,staleTime:0,gcTime:0,refetchInterval:15000});
 function assertLive(captured:BusinessScheduleIdentity,write=false){
  if(!live.current.mounted||getApiActorId()!==captured.actor||!sameBusinessIdentity(live.current.identity,captured)||write&&live.current.readonly)throw new Error('账号、权限或工作区已变化，请重新审阅。');
 }
 async function changed(){await query.refetch();await props.onChanged?.();}
 async function verifyOriginal(original:BusinessScheduleAttempt){
  if(busy)return;const captured={...identity};setBusy(true);setError(undefined);
  try{assertLive(captured);await freshBusinessSession(captured);assertLive(captured);
   const receipt:any=await fetchBusinessScheduleReceipt(captured,original.key);assertLive(captured);
   const reported=normalizeBusinessSchedule(receipt?.entity),current=await fetchBusinessSchedule(captured,reported.id),workflow=await fetchBusinessWorkflow(captured,original.workflowId);assertLive(captured);
   if(!businessReceiptMatches(receipt,original,current,workflow))throw new Error('原回执尚未证明命令完成，请继续只读核验。');
   clearBusinessAttempt(captured,original.key);setJournalVersion(n=>n+1);await changed();assertLive(captured);void message.success('原排程请求已确认');
  }catch(cause){if(live.current.mounted)setError(cause);}finally{if(live.current.mounted)setBusy(false);}
 }
 async function submit(original:BusinessScheduleAttempt,body:unknown,csrf:string){
  assertLive(original,true);if(readBusinessAttempt(original))throw new Error('原排程请求尚未核验。');
  storeBusinessAttempt(original);setJournalVersion(n=>n+1);
  try{await postBusinessScheduleOnce(original,original.action,body,original.key,csrf,original.schedule?.id);assertLive(original,true);
   const receipt:any=await fetchBusinessScheduleReceipt(original,original.key);assertLive(original,true);
   const reported=normalizeBusinessSchedule(receipt?.entity),current=await fetchBusinessSchedule(original,reported.id),workflow=await fetchBusinessWorkflow(original,original.workflowId);assertLive(original,true);
   if(!businessReceiptMatches(receipt,original,current,workflow))throw new Error('原命令回执尚未确认。');
  }catch(cause){storeBusinessAttempt({...original,state:'unknown'});setJournalVersion(n=>n+1);throw cause;}
  clearBusinessAttempt(original,original.key);setJournalVersion(n=>n+1);
  await changed();assertLive(original);
  void message.success(original.action==='author'?'排程已登记，请审批新计划':original.action==='activate'?'激活请求已确认':'撤销请求已确认');
 }
 async function author(values:{notBefore:string;windowStart:string;windowEnd:string}){
  const selected=props.workflowDetail;if(!selected||blocked)return;const captured={...identity},tuple={id:selected.id,revision:selected.revision,planRevision:selected.planRevision,hash:selected.planHash};
  setBusy(true);setError(undefined);
  try{const spec:BusinessScheduleSpec={notBefore:new Date(values.notBefore).toISOString(),windowStart:new Date(values.windowStart).toISOString(),windowEnd:new Date(values.windowEnd).toISOString()};
   assertLive(captured,true);const session=await freshBusinessSession(captured),fresh=await fetchBusinessWorkflow(captured,selected.id);assertLive(captured,true);
   if(fresh.revision!==tuple.revision||fresh.planRevision!==tuple.planRevision||fresh.planHash!==tuple.hash||!businessCanAuthor(fresh,session.user,captured))throw new Error('工单状态或审批记录已变化，请重新审阅。');
   const body=businessAuthorBody(fresh,spec);
   mutationConfirm(modal,{title:'登记业务排程',expected:'schedule-workflow',description:'登记后按新计划重新审批。',onConfirm:async()=>{
    setBusy(true);setError(undefined);
    try{assertLive(captured,true);const latestSession=await freshBusinessSession(captured),latest=await fetchBusinessWorkflow(captured,tuple.id);assertLive(captured,true);
     if(session.csrfToken!==latestSession.csrfToken||latest.revision!==tuple.revision||latest.planRevision!==tuple.planRevision||latest.planHash!==tuple.hash||live.current.workflow?.id!==tuple.id
      ||live.current.workflow.planHash!==tuple.hash||!businessCanAuthor(latest,latestSession.user,captured))throw new Error('会话或工单版本已变化，请重新确认。');
     businessAuthorBody(latest,spec);
     await submit({...captured,action:'author',key:newIdempotencyKey(),workflowId:tuple.id,revision:tuple.revision,planRevision:tuple.planRevision,planHash:tuple.hash,kind:fresh.kind as BusinessSchedule['kind'],spec,state:'pending'},body,latestSession.csrfToken);
     form.resetFields();
    }catch(cause){if(live.current.mounted)setError(cause);throw cause;}finally{if(live.current.mounted)setBusy(false);}
   }});
  }catch(cause){if(live.current.mounted)setError(cause);}finally{if(live.current.mounted)setBusy(false);}
 }
 async function command(row:BusinessSchedule,action:'activate'|'cancel'){
  if(blocked)return;const captured={...identity};setBusy(true);setError(undefined);
  try{assertLive(captured,true);const session=await freshBusinessSession(captured),fresh=await fetchBusinessSchedule(captured,row.id),workflow=await fetchBusinessWorkflow(captured,row.workflowId);assertLive(captured,true);
   if(fresh.revision!==row.revision||!businessCanCommand(fresh,workflow,session.user,captured,action))throw new Error('当前记录尚不满足操作条件，请刷新审批与排程状态。');
   mutationConfirm(modal,{title:action==='activate'?'激活业务排程':'撤销业务排程',expected:`${action}-schedule`,danger:action==='cancel',description:action==='activate'?'调度器将在执行窗口内领取已批准的计划。':'撤销尚未领取的排程。',onConfirm:async()=>{
    setBusy(true);setError(undefined);
    try{assertLive(captured,true);const latestSession=await freshBusinessSession(captured),latest=await fetchBusinessSchedule(captured,row.id),latestWorkflow=await fetchBusinessWorkflow(captured,row.workflowId);assertLive(captured,true);
     if(session.csrfToken!==latestSession.csrfToken||latest.revision!==fresh.revision||latest.workflowPlanHash!==fresh.workflowPlanHash||!businessCanCommand(latest,latestWorkflow,latestSession.user,captured,action))throw new Error('会话、审批版本或排程状态已变化。');
     await submit({...captured,action,key:newIdempotencyKey(),workflowId:latest.workflowId,revision:latest.revision,planRevision:latest.workflowPlanRevision,planHash:latest.workflowPlanHash,kind:latest.kind,schedule:latest,state:'pending'},businessCommandBody(latest,action),latestSession.csrfToken);
    }catch(cause){if(live.current.mounted)setError(cause);throw cause;}finally{if(live.current.mounted)setBusy(false);}
   }});
  }catch(cause){if(live.current.mounted)setError(cause);}finally{if(live.current.mounted)setBusy(false);}
 }
 if(!ready)return <Alert type="info" message="请选择集群与工作区"/>;
 return <Space direction="vertical" size={16} style={{width:'100%'}} data-testid="workflow-business-schedules-panel">
  {!!error&&<QueryError error={error}/>} {!!journalError&&<QueryError error={journalError}/>}
  {attempt&&<Alert type="warning" showIcon message="原排程请求尚未核验" description={<Space wrap><Typography.Text className="mono" copyable>{attempt.key}</Typography.Text><Button loading={busy} onClick={()=>void verifyOriginal(attempt!)}>核验原回执</Button></Space>}/>}
  {props.workflowDetail&&businessCanAuthor(props.workflowDetail,props.actor,identity)&&<Card size="small" title="登记排程"><Descriptions size="small" column={{xs:1,md:2}} items={[{key:'workflow',label:'当前工单',children:<span className="mono" title={props.workflowDetail.id}>{abbreviateId(props.workflowDetail.id)}</span>},{key:'deadline',label:'窗口结束上限',children:formatTime(props.workflowDetail.expiresAt)}]}/>
   <Form form={form} layout="vertical" onFinish={values=>void author(values)} style={{marginTop:16}}><div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(210px,1fr))',gap:16}}>
    {[['notBefore','执行时间（本地）'],['windowStart','窗口开始（含）'],['windowEnd','窗口结束（不含）']].map(([name,label])=><Form.Item key={name} name={name} label={label} rules={[{required:true,message:'请选择时间'}]}><Input type="datetime-local" step={1} max={deadlineMax} disabled={blocked}/></Form.Item>)}
   </div><Button type="primary" htmlType="submit" disabled={blocked} loading={busy}>登记排程</Button></Form></Card>}
  <Card className="table-card" title="业务排程" extra={<Button onClick={()=>void query.refetch()} loading={query.isFetching}>刷新</Button>}>
   {query.error&&<QueryError error={query.error}/>}<Table<BusinessSchedule> rowKey="id" pagination={false} loading={query.isFetching} dataSource={query.data?.items??[]} scroll={{x:1080}} columns={[
    {title:'类型',render:(_,row)=>businessScheduleKinds[row.kind]}, {title:'工单',render:(_,row)=><a href={`/workflows/${row.workflowId}`}>查看工单 · v{row.workflowPlanRevision}</a>},
    {title:'状态',render:(_,row)=><Tag>{businessScheduleLabels[row.state]}</Tag>}, {title:'执行时间',render:(_,row)=>formatTime(row.notBefore)},
    {title:'变更窗口',render:(_,row)=><>{formatTime(row.windowStart)}<div className="table-secondary">至 {formatTime(row.windowEnd)}</div></>},
    {title:'执行人',render:(_,row)=><Typography.Text className="mono" copyable={{text:row.executorId}}>{row.executorId===props.actor.id?(props.actor.displayName??props.actor.username):abbreviateId(row.executorId)}</Typography.Text>}, {title:'状态原因',render:(_,row)=>row.reasonCode??'—'},
    {title:'操作',render:(_,row)=><Space><Button type="link" disabled={blocked||row.state!=='pending-approval'||row.claimId!==null||!businessWholeWorkspace(props.actor,identity,row.executorId===identity.actor?'write':'approve')} onClick={()=>void command(row,'activate')}>激活</Button>
     <Button type="link" danger disabled={blocked||row.executorId!==identity.actor||!['pending-approval','active'].includes(row.state)||row.claimId!==null||!businessWholeWorkspace(props.actor,identity,'write')} onClick={()=>void command(row,'cancel')}>撤销</Button></Space>},
   ]}/><CursorPagination pages={pages} nextCursor={query.data?.nextCursor} count={query.data?.items.length??0} size={20} loading={query.isFetching}/>
  </Card>
 </Space>;
}

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { build } from 'esbuild';
import { chromium, type Browser, type Page } from '@playwright/test';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

// Source-only browser: real React 18 effects and the actual component/model;
// only product dependencies and HTTP transport are fixtures. No server is used.
const component = resolve('apps/console-web/src/features/EntityAnnotations.tsx');
const relatedComponents = {
  'target-under-test': { path: resolve('apps/console-web/src/features/TargetManager.tsx'), exports: 'TargetApprovalDrawer' },
  'credential-under-test': { path: resolve('apps/console-web/src/features/CredentialManager.tsx'), exports: 'CredentialApprovalDrawer' },
};
const harness = String.raw`
import React, {useEffect} from 'react';
import {createRoot} from 'react-dom/client';
import {flushSync} from 'react-dom';
import {EntityAnnotations, AnnotationApprovalDrawer} from 'annotation-under-test';
import {TargetManager, TargetApprovalDrawer} from 'target-under-test';
import {CredentialApprovalDrawer} from 'credential-under-test';
const scope={actor:'b0d46823-d29f-45c3-a744-5d332b066555',version:'strict-current-version',cid:'cd69757e-8f3e-4b7a-a671-3bb113d365d6',wid:'ef4d7bda-a50c-4e97-bf58-a10c7fedc132',mode:'approval',entityType:'services',entityId:'6b09d997-d36b-47d8-9ded-4bc2b28546e4'};
const frame=globalThis.__annotationFrame={scope,actor:scope.actor,version:scope.version,cid:scope.cid,wid:scope.wid,mode:'approval',allowed:true,ability:true,ready:true,blocked:false,status:'active',calls:[],setups:0,cleanups:0,dialog:null,pause:false,release:null};
frame.row={cluster_id:scope.cid,entity_type:'services',kong_id:scope.entityId,description:'before',owner_user_id:null,metadata:{team:'payments'},revision:3,status:'active'};
frame.entity={id:scope.entityId,name:'payments',tags:['workspace:payments']};
frame.credentialId='8e4e925a-40f4-49a3-89c4-ef7ed58a6bde';frame.resets=0;
frame.form={resetFields(){frame.resets++},setFieldsValue(){},setFieldValue(){},submit(){}};
const stored=new Map();Object.defineProperty(globalThis,'sessionStorage',{configurable:true,value:{getItem:k=>stored.get(k)??null,setItem:(k,v)=>stored.set(k,v),removeItem:k=>stored.delete(k)}});
frame.api=async(path,options={})=>{
 frame.calls.push({path,method:options.method??'GET'});
 if(path==='/auth/me') {const value={user:{id:scope.actor,permissionsVersion:scope.version,forcePasswordChange:false},csrfToken:'source-only-current-csrf-43-characters-value'};if(frame.pause)await new Promise(done=>{frame.release=done});return value;}
 if(path.includes('/annotation-changes/prepare?'))return {intentId:'a7d13665-be4e-4438-8424-007e763646fe',clusterId:scope.cid,workspaceId:scope.wid,entityType:scope.entityType,entityId:scope.entityId,operation:'set',annotationRevision:3,state:'prepared',revision:null,planHash:null,materialHmac:'a'.repeat(64),workflowId:null,expiresAt:new Date(Date.now()+3600000).toISOString(),nativeRequestsSent:0,nativeExecutionAvailable:false,capabilities:{submit:true},preview:{before:frame.row,after:{entityType:scope.entityType,entityId:scope.entityId,operation:'set',input:{revision:3,description:'after',owner_user_id:null}},confirmationName:'payments',retentionDays:null}};
 if(path.includes('/entity-changes/prepare?')){
  const change=JSON.parse(options.body).change,target=change.kind==='target';
  const nativeId=target?'fd2280f0-e6f6-48d3-a7e5-95511bd8104b':frame.credentialId;
  frame.intent={id:'a7d13665-be4e-4438-8424-007e763646fe',revision:1,materialHmac:'a'.repeat(64),executionMode:'approval',issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString(),nativeExecutionAvailable:false,capabilities:{submit:true},workflowId:null,
   ...(target?{targetSubject:{upstreamId:scope.entityId,action:'create'}}:{credentialSubject:{consumerId:scope.entityId,credentialKind:'key-auth',action:'delete',credentialId:frame.credentialId}}),
   review:{clusterId:scope.cid,workspaceId:scope.wid,changes:[{entityType:target?'targets':'key-auth',nativeId,action:target?'create':'delete',before:target?null:{id:frame.credentialId,consumer:{id:scope.entityId},username:'source-public-name'},after:target?{id:nativeId,target:'api.internal:8080',weight:100,upstream:{id:scope.entityId}}:null}],impact:{changedObjects:1,nativePackets:1,trafficAvailability:'unavailable',globalPlugin:false},recovery:{state:'baseline-required',blockerCodes:['EXECUTION_BASELINE_REQUIRED']}}};
  return frame.intent;
 }
 if(path.includes('/entity-changes/a7d13665-be4e-4438-8424-007e763646fe?'))return frame.intent;
 throw Error('UNEXPECTED_SOURCE_TRANSPORT');
};
function Probe(){useEffect(()=>{frame.setups++;return()=>{frame.cleanups++}},[]);return null;}
const root=createRoot(document.getElementById('root'));
let kind='drawer';
function render(){root.render(<React.StrictMode><Probe/>{kind==='parent'?<EntityAnnotations type='services' entity={frame.entity}/>:kind==='target-parent'?<TargetManager upstreamId={scope.entityId} parentEntity={frame.entity}/>:kind==='target'?<TargetApprovalDrawer scope={{...scope,upstreamId:scope.entityId}} draft={{action:'create',body:{target:'api.internal:8080',weight:100},targetName:'api.internal:8080'}} rows={[]} healthItems={[]} onChange={()=>{}} onClose={()=>{}}/>:kind==='credential'?<CredentialApprovalDrawer scope={{...scope,consumerId:scope.entityId,credentialKind:'key-auth'}} selection={{action:'delete',credentialId:frame.credentialId}} onChange={()=>{}} onClose={()=>{}}/>:<AnnotationApprovalDrawer scope={scope} entity={frame.entity} draft={{operation:'set',annotationRevision:3,input:{revision:3,description:'after',owner_user_id:null},confirmationName:'payments'}} onClose={()=>{}} onChange={()=>{}}/>}</React.StrictMode>);}
globalThis.__annotationControl={start(value='drawer'){kind=value;render()},patch(value){Object.assign(frame,value);flushSync(render)},unmount(){root.unmount()},release(){frame.release?.()},confirm(){return frame.dialog?.onConfirm()},info(){return{calls:frame.calls,setups:frame.setups,cleanups:frame.cleanups,resets:frame.resets,stored:[...stored.values()].map(value=>JSON.parse(value)),text:document.body.textContent}}};
`;

const stubs: Record<string, string> = {
  antd: String.raw`
import React from 'react';const h=React.createElement,frame=()=>globalThis.__annotationFrame;
const Box=({children,extra})=>h('div',null,extra,children);
export const Button=({children,onClick,disabled,loading})=>h('button',{onClick,disabled:disabled||loading},children);
export const Card=Box,Space=Box,Tag=Box,InputNumber=Box,Select=Box,Table=Box,Checkbox=Box,Spin=Box,Tabs=Box;
export const Alert=({message,description})=>h('div',{role:'alert'},message,description);
export const Descriptions=({items})=>h('div',null,items.map(v=>h('div',{key:v.key},v.label,v.children)));
export const Drawer=({open,title,children,extra})=>open?h('section',null,h('h2',null,title),extra,children):null;
export const Modal=({open,title,children})=>open?h('div',{role:'dialog'},title,children):null;
export const Form=Object.assign(Box,{Item:Box,useForm:()=>[frame().form]});
export const Input=Object.assign(Box,{TextArea:Box});
export const Typography={Text:Box,Paragraph:Box,Title:Box};
export const App={useApp:()=>({modal:{},message:{success(){}}})};`,
  '@tanstack/react-query': `export const useQuery=options=>{const f=globalThis.__annotationFrame,k=options.queryKey[0];const data=k==='targets'||k==='target-health'?{items:[]}:k==='credential-workflow-parent'?{entity:{id:f.scope.entityId}}:k==='credential-workflow-before'?{entity:{id:f.credentialId,consumer:{id:f.scope.entityId},username:'source-public-name'}}:k==='credential-workflow-schema'?undefined:f.row;return{data,isError:false,refetch:async()=>({data})}};export const useQueryClient=()=>({invalidateQueries:async()=>{}});export const useMutation=()=>({isPending:false,mutate(){throw Error('DIRECT_WRITE_FORBIDDEN')}});`,
  '@ant-design/icons': `export const PlusOutlined=()=>null,ReloadOutlined=()=>null;`,
  'react-router-dom': `export const useNavigate=()=>()=>{throw Error('UNEXPECTED_NAVIGATION')};`,
  'ClusterContext': `export const useCluster=()=>({clusterId:globalThis.__annotationFrame.cid,cluster:{execution_mode:globalThis.__annotationFrame.mode}});`,
  'WorkspaceContext': `export const useWorkspace=()=>({workspaceId:globalThis.__annotationFrame.wid,ready:globalThis.__annotationFrame.ready,writeBlocked:globalThis.__annotationFrame.blocked,readonlyWorkspace:false,workspace:{status:globalThis.__annotationFrame.status}});`,
  'AuthContext': `export const useAuth=()=>({user:{id:globalThis.__annotationFrame.actor,permissionsVersion:globalThis.__annotationFrame.version,capabilities:{platformAdmin:true,grants:[]}}});`,
  'Permissions': `export const usePermissions=()=>({can:()=>globalThis.__annotationFrame.allowed});`,
  'EntityPermissions': `export const useEntityPermissions=()=>({can:()=>globalThis.__annotationFrame.ability,query:{isError:false}});`,
  'client': `export class ApiError extends Error{constructor(message,status,code){super(message);this.status=status;this.code=code}}export const api=(...a)=>globalThis.__annotationFrame.api(...a);export const getApiActorId=()=>globalThis.__annotationFrame.actor;export const errorMessage=value=>value.message;`,
  'schema-patch': `export const hasHiddenValue=value=>JSON.stringify(value).includes('[REDACTED]');`,
  'MutationConfirm': `export const mutationConfirm=(_,options)=>{globalThis.__annotationFrame.dialog=options};`,
  'Shared': `import React from 'react';export const QueryError=({error})=>React.createElement('div',{role:'alert'},error.message);export const formatTime=value=>value;`,
  'entities': `export const entityName=value=>value.name||value.username||value.id;export const entityTime=value=>value;export const isEntityType=value=>['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis'].includes(value);`,
  'CursorPagination': `export const CursorPagination=()=>null;export const useCursorPages=()=>({cursor:undefined});`,
  'KongSchemaForm': `export const KongSchemaForm=()=>null;export const prepareFormValues=(_,value)=>value;export const schemaFields=()=>[];`,
  'EntityEditor': `export const EntityEditor=()=>null;`,
  'IAMLookups': `export const PagedIAMLookup=()=>null;`,
  'm7.redaction': `export const safeJsonPreview=value=>JSON.stringify(value);`,
};

async function bundle(legacyCleanup = false) {
  const result = await build({
    stdin: { contents: harness, resolveDir: process.cwd(), sourcefile: 'annotation-strict-source.tsx', loader: 'tsx' },
    bundle: true, write: false, format: 'iife', platform: 'browser', jsx: 'automatic',
    define: { 'process.env.NODE_ENV': '"development"' },
    plugins: [{ name: 'offline-annotation-source-dependencies', setup(plugin) {
      plugin.onResolve({ filter: /^annotation-under-test$/ }, () => ({ path: component, namespace: 'annotation-source' }));
      plugin.onResolve({ filter: /^(target|credential)-under-test$/ }, args => ({ path: relatedComponents[args.path as keyof typeof relatedComponents].path, namespace: 'annotation-source' }));
      plugin.onLoad({ filter: /\/EntityAnnotations\.tsx$/, namespace: 'annotation-source' }, () => {
        let source = readFileSync(component, 'utf8');
        if (legacyCleanup) source = source.replaceAll('useEffect(() => { latest.current.active = true; return () => { latest.current.active = false; }; }, []);', 'useEffect(() => () => { latest.current.active = false; }, []);');
        return { contents: `${source}\nexport { AnnotationApprovalDrawer };`, loader: 'tsx', resolveDir: resolve(component, '..') };
      });
      plugin.onLoad({ filter: /\/(TargetManager|CredentialManager)\.tsx$/, namespace: 'annotation-source' }, args => {
        const exported = Object.values(relatedComponents).find(value => value.path === args.path)!;
        return { contents: `${readFileSync(args.path, 'utf8')}\nexport { ${exported.exports} };`, loader: 'tsx', resolveDir: resolve(args.path, '..') };
      });
      plugin.onResolve({ filter: /.*/ }, args => {
        const name = args.path.split('/').at(-1)!;
        if (Object.hasOwn(stubs, args.path)) return { path: args.path, namespace: 'annotation-stub' };
        if (args.path.startsWith('.') && Object.hasOwn(stubs, name)) return { path: name, namespace: 'annotation-stub' };
      });
      plugin.onLoad({ filter: /.*/, namespace: 'annotation-stub' }, args => ({ contents: stubs[args.path], loader: 'js', resolveDir: process.cwd() }));
    } }],
  });
  return result.outputFiles[0].text;
}

let browser: Browser, source: string, legacy: string;
beforeAll(async () => {
  [source, legacy] = await Promise.all([bundle(), bundle(true)]);
  browser = await chromium.launch({ executablePath: !process.env.CI && !existsSync(chromium.executablePath()) && existsSync('/usr/bin/chromium') ? '/usr/bin/chromium' : undefined, headless: true, args: ['--no-sandbox'] });
}, 30_000);
afterAll(async () => { await browser?.close(); });
async function pageFor(code = source) {
  const page = await browser.newPage();
  // Any accidental fetch is a test failure; all responses below are in-memory.
  const network: string[] = [];
  await page.route('**/*', route => { network.push(route.request().url()); return route.abort(); });
  await page.setContent('<!doctype html><div id="root"></div>');
  await page.addScriptTag({ content: code });
  return { page, network };
}
async function info(page: Page) { return page.evaluate(() => (globalThis as any).__annotationControl.info()); }
async function start(page: Page, kind = 'drawer') {
  await page.evaluate(value => (globalThis as any).__annotationControl.start(value), kind);
  await expect.poll(async () => (await info(page)).setups).toBe(2);
  expect((await info(page)).cleanups).toBe(1);
}
async function press(page: Page, text: string) { await page.getByRole('button', { name: text, exact: true }).click(); }

describe('actual React StrictMode annotation mount-cleanup-setup lifecycle, offline Source-only', () => {
  it('reproduces the old cleanup-only defect without issuing any fixture POST', async () => {
    const { page, network } = await pageFor(legacy);
    try {
      await start(page); await press(page, '生成审批预览');
      await expect.poll(async () => (await info(page)).text).toContain('账号、权限或实体说明范围已变化。');
      expect((await info(page)).calls).toEqual([]); expect((await info(page)).stored).toEqual([]); expect(network).toEqual([]);
    } finally { await page.close(); }
  });

  it('allows the first explicit prepare after genuine StrictMode replay exactly once', async () => {
    const { page, network } = await pageFor();
    try {
      await start(page); await press(page, '生成审批预览');
      await expect.poll(async () => await page.getByRole('button', { name: '提交审批', exact: true }).count()).toBe(1);
      const result = await info(page);
      expect(result.calls.filter((v: any) => v.method === 'POST')).toHaveLength(1);
      expect(result.calls[0].path).toBe('/auth/me'); expect(result.stored[0].state).toBe('prepared');
      expect(result.calls.some((v: any) => /entity-annotations|\/execute/.test(v.path))).toBe(false); expect(network).toEqual([]);
    } finally { await page.close(); }
  });

  it.each([
    ['permission', { allowed: false }], ['entity ability', { ability: false }], ['permission version', { version: 'revoked-version' }],
    ['actor', { actor: 'e77777b2-e286-4a6e-807d-359c7ca263b6' }], ['cluster', { cid: 'e77777b2-e286-4a6e-807d-359c7ca263b6' }],
    ['workspace', { wid: 'e77777b2-e286-4a6e-807d-359c7ca263b6' }], ['execution mode', { mode: 'direct' }], ['workspace state', { status: 'disabled' }],
  ])('keeps the %s fence after an awaited current-session response', async (_reason, patch) => {
    const { page, network } = await pageFor();
    try {
      await start(page); await page.evaluate(() => { (globalThis as any).__annotationFrame.pause = true; });
      await press(page, '生成审批预览');
      await expect.poll(async () => (await info(page)).calls.length).toBe(1);
      await page.evaluate(value => (globalThis as any).__annotationControl.patch(value), patch);
      await expect.poll(async () => await page.getByRole('button', { name: '生成审批预览', exact: true }).isDisabled()).toBe(true);
      await page.evaluate(() => (globalThis as any).__annotationControl.release());
      await expect.poll(async () => (await info(page)).text).toContain('账号、权限或实体说明范围已变化。');
      expect((await info(page)).calls.every((v: any) => v.method === 'GET')).toBe(true); expect((await info(page)).stored).toEqual([]); expect(network).toEqual([]);
    } finally { await page.close(); }
  });

  it('rejects an in-flight prepare after a real React unmount without persisting or posting', async () => {
    const { page, network } = await pageFor();
    try {
      await start(page); await page.evaluate(() => { (globalThis as any).__annotationFrame.pause = true; });
      await press(page, '生成审批预览'); await expect.poll(async () => (await info(page)).calls.length).toBe(1);
      await page.evaluate(() => { (globalThis as any).__annotationControl.unmount(); (globalThis as any).__annotationControl.release(); });
      await page.evaluate(() => new Promise(resolve => setTimeout(resolve, 0)));
      expect((await info(page)).cleanups).toBe(2); expect((await info(page)).stored).toEqual([]);
      expect((await info(page)).calls.every((v: any) => v.method === 'GET')).toBe(true); expect(network).toEqual([]);
    } finally { await page.close(); }
  });

  it('keeps the parent typed remove handoff alive after replay and performs no Direct write', async () => {
    const { page, network } = await pageFor();
    try {
      await start(page, 'parent'); await press(page, '删除说明');
      await page.evaluate(() => (globalThis as any).__annotationControl.confirm());
      await expect.poll(async () => (await info(page)).text).toContain('实体说明变更审批');
      expect((await info(page)).text).toContain('删除说明'); expect((await info(page)).calls).toEqual([]); expect(network).toEqual([]);
    } finally { await page.close(); }
  });

  it('allows the first Target create preview after real StrictMode replay', async () => {
    const { page, network } = await pageFor();
    try {
      await start(page, 'target'); await press(page, '生成审批预览');
      await expect.poll(async () => (await info(page)).stored[0]?.state).toBe('prepared');
      expect((await info(page)).calls.filter((value: any) => value.method === 'POST')).toHaveLength(1);
      expect((await info(page)).calls[0].path).toBe('/auth/me'); expect(network).toEqual([]);
    } finally { await page.close(); }
  });

  it('allows the Target parent first create entry after replay without a Direct write', async () => {
    const { page, network } = await pageFor();
    try {
      await start(page, 'target-parent'); await press(page, '添加 Target');
      await expect.poll(async () => await page.getByRole('dialog').count()).toBe(1);
      expect((await info(page)).text).not.toContain('账号、权限或当前 Target 已变化');
      expect((await info(page)).calls).toEqual([]); expect(network).toEqual([]);
    } finally { await page.close(); }
  });

  it('allows the first typed credential delete preview and preserves resetFields cleanup', async () => {
    const { page, network } = await pageFor();
    try {
      await start(page, 'credential');
      expect((await info(page)).resets).toBe(1);
      await press(page, '生成变更预览'); await page.evaluate(() => (globalThis as any).__annotationControl.confirm());
      await expect.poll(async () => (await info(page)).stored[0]?.state).toBe('prepared');
      expect((await info(page)).calls.filter((value: any) => value.method === 'POST')).toHaveLength(1);
      expect((await info(page)).calls.every((value: any) => !/credentials|\/execute/.test(value.path))).toBe(true);
      const before = (await info(page)).resets;
      await page.evaluate(() => (globalThis as any).__annotationControl.unmount());
      expect((await info(page)).resets).toBe(before + 1); expect(network).toEqual([]);
    } finally { await page.close(); }
  });
});

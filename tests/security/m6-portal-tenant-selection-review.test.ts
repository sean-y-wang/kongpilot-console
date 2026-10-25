import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {createHash,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {createContext,runInContext} from 'node:vm';
import ts from 'typescript';
import * as selection from '../../apps/portal-web/src/app/tenant-selection';
import * as api from '../../apps/portal-web/src/api/portal-client';

const tenant=(slug:string)=>({slug,clusterId:randomUUID(),workspaceId:randomUUID(),name:slug,branding:{},registrationEnabled:true});
const A=tenant('independent-a'),B=tenant('independent-b');
function memoryStorage(){
 const values=new Map<string,string>();
 return{values,getItem:vi.fn((key:string)=>values.get(key)??null),setItem:vi.fn((key:string,value:string)=>{values.set(key,value);}),removeItem:vi.fn((key:string)=>{values.delete(key);})};
}
beforeEach(()=>{api.clearPortalSession();api.setPortalScope(undefined);});
afterEach(()=>{vi.unstubAllGlobals();api.clearPortalSession();api.setPortalScope(undefined);});

/** Executes the actual PortalRoot declaration; React hooks/query/storage are
 * controlled in memory. The application's ReactDOM entry and HTTP are absent. */
function actualRoot(search:string,storage=memoryStorage()){
 vi.stubGlobal('sessionStorage',storage);
 const source=readFileSync('apps/portal-web/src/main.tsx','utf8');
 const tree=ts.createSourceFile('main.tsx',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
 const declaration=tree.statements.find(s=>ts.isFunctionDeclaration(s)&&s.name?.text==='PortalRoot');
 if(!declaration)throw Error('Actual PortalRoot declaration absent');
 const code=ts.transpileModule(declaration.getText(tree)+'\nexports.root=PortalRoot;',{compilerOptions:{jsx:ts.JsxEmit.React,module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
 let initialized=false,slug:string|undefined;
 const ref={current:undefined as string|undefined},effects:Array<()=>void>=[],location={search};
 const query:any={data:undefined,isFetching:false,error:undefined},config:any[]=[];
 const clear=vi.fn(),publicRead=vi.fn(async()=>query.data);
 const createElement=(type:any,props:any,...children:any[])=>({type,props:{...props,children:children.length===1?children[0]:children}});
 const exports:any={};
 runInContext(code,createContext({exports,React:{createElement},location,
  useState(initial:any){if(!initialized){slug=typeof initial==='function'?initial():initial;initialized=true;}return[slug,(value:string|undefined)=>{slug=value;}];},
  useRef(initial:string|undefined){if(ref.current===undefined&&slug!==undefined)ref.current=initial;return ref;},
  useEffect(fn:()=>void){effects.push(fn);},useQuery(options:any){config.push(options);return query;},
  initialPortalTenantSlug:selection.initialPortalTenantSlug,matchedPortalTenant:selection.matchedPortalTenant,
  rememberResolvedPortalTenant:selection.rememberResolvedPortalTenant,validPortalTenantSlug:selection.validPortalTenantSlug,
  clearPortalSelectionStorage:selection.clearPortalSelectionStorage,clearPortalSession:api.clearPortalSession,setPortalScope:api.setPortalScope,
  portalRequest:publicRead,client:{clear},TenantPicker:'TenantPicker',PortalProvider:'PortalProvider',PortalLayout:'PortalLayout',PortalErrorView:'PortalErrorView',Alert:'Alert',Button:'Button',Spin:'Spin',
 }));
 return{root:()=>exports.root(),query,config,effects,location,storage,clear,publicRead,ref,
  flush(){effects.splice(0).forEach(fn=>fn());},getSlug:()=>slug,
  reload(nextSearch=''){initialized=false;slug=undefined;ref.current=undefined;location.search=nextSearch;effects.length=0;},
 };
}

describe('independent tenant hint and resolved scope boundaries',()=>{
 it('treats stored slug as a hint requiring a current public resolution, never as stored authorization',()=>{
  const storage=memoryStorage();storage.values.set(selection.portalTenantStorageKey,A.slug);
  expect(selection.initialPortalTenantSlug('',storage)).toBe(A.slug);
  expect(selection.matchedPortalTenant(A.slug,undefined)).toBeUndefined();
  expect(selection.rememberResolvedPortalTenant(A.slug,undefined,storage)).toBe(false);
  expect(storage.setItem).not.toHaveBeenCalled();
 });
 it('uses an explicit tenant URL instead of an old hint and stores neither CID/WID nor credentials',()=>{
  const storage=memoryStorage();storage.values.set(selection.portalTenantStorageKey,B.slug);
  expect(selection.initialPortalTenantSlug('?tenant='+A.slug,storage)).toBe(A.slug);
  expect(storage.values.get(selection.portalTenantStorageKey)).toBe(B.slug);
  expect(selection.rememberResolvedPortalTenant(A.slug,A,storage)).toBe(true);
  expect([...storage.values]).toEqual([[selection.portalTenantStorageKey,A.slug]]);
 });
 it.each(['%2Fforeign','%2E%2E','-space','UPPER','a'.repeat(81)])('does not borrow old scope when explicit query is invalid: %s',value=>{
  const storage=memoryStorage();storage.values.set(selection.portalTenantStorageKey,A.slug);
  expect(selection.initialPortalTenantSlug('?tenant='+value,storage)).toBeUndefined();
  expect(storage.getItem).not.toHaveBeenCalled();
 });
 it.each([
  ['other selected slug',{...A,slug:B.slug}],['missing cluster',{...A,clusterId:undefined}],
  ['missing workspace',{...A,workspaceId:undefined}],['malformed UUID',{...A,workspaceId:'00000000-0000-0000-0000-000000000000'}],
  ['array',[A]],
 ])('refuses public resolution %s without persisting anything',(_reason,resolved)=>{
  const storage=memoryStorage();expect(selection.matchedPortalTenant(A.slug,resolved)).toBeUndefined();
  expect(selection.rememberResolvedPortalTenant(A.slug,resolved,storage)).toBe(false);expect(storage.setItem).not.toHaveBeenCalled();
 });
 it('does not replace an already verified B hint with a late A response',()=>{
  const storage=memoryStorage();selection.rememberResolvedPortalTenant(B.slug,B,storage);
  expect(selection.rememberResolvedPortalTenant(B.slug,A,storage)).toBe(false);
  expect(storage.values.get(selection.portalTenantStorageKey)).toBe(B.slug);
 });
});

describe('actual PortalRoot independent query/effect wiring',()=>{
 it('resolves URL tenant publicly, commits only the validated hint, and reloads a query-free application URL',async()=>{
  const f=actualRoot('?tenant='+A.slug);f.root();
  expect(f.getSlug()).toBe(A.slug);expect(f.config[0].queryKey).toEqual(['public-portal-tenant',A.slug]);
  const signal=new AbortController().signal;await f.config[0].queryFn({signal});
  expect(f.publicRead).toHaveBeenCalledWith('/tenants/'+A.slug,undefined,{signal},false);
  f.flush();expect(f.storage.values.size).toBe(0);
  f.query.data=A;const provider=f.root();expect(provider.type).toBe('PortalProvider');expect(provider.props.tenant).toBe(A);
  expect(f.storage.values.size).toBe(0);f.flush();expect([...f.storage.values]).toEqual([[selection.portalTenantStorageKey,A.slug]]);
  f.reload('');const reloaded=f.root();expect(reloaded.type).toBe('PortalProvider');expect(reloaded.props.tenant).toBe(A);expect(f.getSlug()).toBe(A.slug);
 });
 it('select clears authenticated scope/cache/recovery before B resolution and fences the previously queued A effect',()=>{
  const f=actualRoot('?tenant='+A.slug);f.query.data=A;
  api.setPortalScope(A);api.setPortalIdentity({...A,id:randomUUID()});
  f.storage.values.set(api.portalRecoveryStorageKey,'synthetic-reference');f.storage.values.set('unrelated','retain');
  const providerA=f.root(),queuedA=f.effects.shift()!;
  providerA.props.children.props.changeTenant();
  expect(api.getPortalScope()).toBeUndefined();expect(api.getPortalIdentity()).toBeUndefined();expect(f.clear).toHaveBeenCalledOnce();
  expect(f.storage.values).toEqual(new Map([['unrelated','retain']]));
  const picker=f.root();expect(picker.type).toBe('TenantPicker');picker.props.onSelect(B.slug);
  expect(f.getSlug()).toBe(B.slug);expect(f.storage.setItem).not.toHaveBeenCalled();
  queuedA();expect(f.storage.values.has(selection.portalTenantStorageKey)).toBe(false);
  expect(f.root().type).not.toBe('PortalProvider');f.flush();expect(f.storage.values.has(selection.portalTenantStorageKey)).toBe(false);
  f.query.data=B;const providerB=f.root();f.flush();
  expect(providerB.props.tenant).toBe(B);expect(f.storage.values.get(selection.portalTenantStorageKey)).toBe(B.slug);
 });
 it('does not derive tenant from authenticated identity or cookie claims when the URL and stored hint are absent',()=>{
  const f=actualRoot('');api.setPortalScope(B);api.setPortalIdentity({...B,id:randomUUID()});
  Object.defineProperty(globalThis,'document',{configurable:true,get(){throw Error('Cookie scope inference forbidden');}});
  try{f.query.data=B;expect(f.root().type).toBe('TenantPicker');f.flush();expect(f.storage.values.size).toBe(0);expect(f.config[0].enabled).toBe(false);}
  finally{delete(globalThis as any).document;}
 });
 it('renders neither malformed nor mismatched data as an authenticated provider',()=>{
  const f=actualRoot('?tenant='+B.slug);f.query.data=A;
  expect(f.root().type).not.toBe('PortalProvider');f.flush();expect(f.storage.values.size).toBe(0);
  f.query.data={...B,workspaceId:'invalid'};expect(f.root().type).not.toBe('PortalProvider');f.flush();expect(f.storage.values.size).toBe(0);
 });
 it('keeps the in-memory tenant available when all storage operations are denied',()=>{
  const storage=memoryStorage();for(const fn of [storage.getItem,storage.setItem,storage.removeItem])fn.mockImplementation(()=>{throw Error('Storage denied');});
  const f=actualRoot('?tenant='+A.slug,storage);f.query.data=A;const provider=f.root();expect(()=>f.flush()).not.toThrow();
  expect(provider.props.tenant).toBe(A);expect(()=>provider.props.children.props.changeTenant()).not.toThrow();
  const picker=f.root();expect(()=>picker.props.onSelect(B.slug)).not.toThrow();expect(f.getSlug()).toBe(B.slug);
 });
 it('handles the browser sessionStorage getter throwing without falling back to identity',()=>{
  const f=actualRoot('?tenant='+A.slug);Object.defineProperty(globalThis,'sessionStorage',{configurable:true,get(){throw new DOMException('Unavailable','SecurityError');}});
  f.query.data=A;expect(f.root().props.tenant).toBe(A);expect(()=>f.flush()).not.toThrow();
  f.reload('');expect(f.root().type).toBe('TenantPicker');expect(f.getSlug()).toBeUndefined();
 });
 it('keeps the real browser detail navigation query-free instead of masking the product defect in the test',()=>{
  const browser=readFileSync('tests/e2e/m6.spec.ts','utf8');
  expect(browser).toContain('page.goto(`/applications/${fixture.applicationId}`)');
  expect(browser).not.toContain('page.goto(`/applications/${fixture.applicationId}?tenant=');
 });
 it('uses the reviewed tenant helper and rebranded main without changing PortalRoot selection wiring',()=>{
  const sha=(path:string)=>createHash('sha256').update(readFileSync(path)).digest('hex');
  expect(sha('apps/portal-web/src/app/tenant-selection.ts')).toBe('4ecf8a01ba40609db54ae305c228480d8e491677e912fdb7a87c2a72d625c664');
  // Product UI review: PortalRoot and tenant helper are unchanged; the palette fallback and nonessential footer copy changed.
  expect(sha('apps/portal-web/src/main.tsx')).toBe('d812b99966f09899c0e9a31d35b57e778c1ea69c4020d4a89bef3dbd285b7944');
 });
});

import {BadRequestException,Injectable} from '@nestjs/common';
import {isAlias,isMap,isSeq,parseDocument} from 'yaml';
import {SecretService} from '../../infrastructure/secret.service';

const MAX_BYTES=3*1024*1024,MAX_DEPTH=32,MAX_NODES=50000;
const methods=new Set(['get','put','post','delete','options','head','patch','trace']);
const forbiddenNames=new Set(['__proto__','prototype','constructor']);
const scalarTags=new Set(['tag:yaml.org,2002:str','tag:yaml.org,2002:int','tag:yaml.org,2002:float','tag:yaml.org,2002:bool','tag:yaml.org,2002:null','tag:yaml.org,2002:map','tag:yaml.org,2002:seq']);
function fail(code='PORTAL_DOCUMENT_INVALID'):never{throw new BadRequestException({code,message:'文档格式无效或包含不允许公开的内容'});}
const record=(value:unknown):value is Record<string,any>=>Boolean(value)&&typeof value==='object'&&!Array.isArray(value);
function decodeEntities(value:string):string {
  return value.replace(/&amp;/gi,'&').replace(/&lt;/gi,'<').replace(/&gt;/gi,'>')
    .replace(/&#(?:x([a-f\d]+)|(\d+));?/gi,(_,hex,decimal)=>String.fromCharCode(parseInt(hex||decimal,hex?16:10)))
    .replace(/&colon;/gi,':').replace(/&Tab;|&NewLine;/gi,' ');
}
function unsafeText(value:string):boolean {
  const decoded=decodeEntities(value),compact=decoded.replace(/[\u0000-\u0020]/g,'').replace(/\\/g,'/');
  return /<\/?[a-z][^>]*>|<!--|<!doctype|<\?/i.test(decoded)||/(?:[a-z][a-z\d+.-]*:)?\/\/[^/\s]*@/i.test(compact)||/(?:javascript|vbscript|data):/i.test(compact);
}

/** Validates untrusted documents without fetching refs or rendering HTML. */
@Injectable()
export class PortalDocumentService {
  constructor(private readonly secrets:SecretService){}

  parse(input:string|object,publicProxyOrigin:string|null):{document:any;hash:string;report:Record<string,unknown>} {
    let source:unknown=input;
    if(typeof input==='string'){
      if(Buffer.byteLength(input)>MAX_BYTES)fail('PORTAL_DOCUMENT_TOO_LARGE');
      try{
        if(/^\s*[\[{]/.test(input))source=JSON.parse(input);
        else{
          const parsed=parseDocument(input,{schema:'core',uniqueKeys:true,strict:true});
          if(parsed.errors.length||parsed.warnings.length)fail();
          let astNodes=0;
          const inspect=(node:any,depth:number):void=>{
            if(node==null)return;
            if(++astNodes>MAX_NODES||depth>MAX_DEPTH)fail('PORTAL_DOCUMENT_BUDGET_EXCEEDED');
            if(isAlias(node)||node.anchor||node.tag&&!scalarTags.has(node.tag))fail('PORTAL_DOCUMENT_YAML_FEATURE_FORBIDDEN');
            if(isMap(node))for(const pair of node.items){inspect(pair.key,depth+1);inspect(pair.value,depth+1);}
            else if(isSeq(node))for(const child of node.items)inspect(child,depth+1);
          };
          inspect(parsed.contents,0);source=parsed.toJS({maxAliasCount:0});
        }
      }catch(error){if(error instanceof BadRequestException)throw error;fail();}
    }
    let nodes=0,bytes=0;
    const seen=new WeakSet<object>();
    const clone=(value:unknown,depth:number):any=>{
      if(++nodes>MAX_NODES||depth>MAX_DEPTH)fail('PORTAL_DOCUMENT_BUDGET_EXCEEDED');
      if(value===null||typeof value==='boolean')return value;
      if(typeof value==='number'){if(!Number.isFinite(value))fail();return value;}
      if(typeof value==='string'){bytes+=Buffer.byteLength(value);if(bytes>MAX_BYTES)fail('PORTAL_DOCUMENT_TOO_LARGE');if(unsafeText(value))fail('PORTAL_DOCUMENT_UNSAFE_TEXT');return value;}
      if(typeof value!=='object'||value===null||seen.has(value))fail();
      seen.add(value);
      const proto=Object.getPrototypeOf(value);
      if(Array.isArray(value)){
        if(proto!==Array.prototype||Object.getOwnPropertySymbols(value).length)fail();
        const descriptors=Object.getOwnPropertyDescriptors(value),output=[];
        if(Object.keys(descriptors).some(name=>name!=='length'&&(!/^(?:0|[1-9]\d*)$/.test(name)||Number(name)>=value.length)))fail();
        for(let index=0;index<value.length;index++){const item=descriptors[String(index)];if(!item||!Object.hasOwn(item,'value'))fail();output.push(clone(item.value,depth+1));}
        return output;
      }
      if(proto!==Object.prototype&&proto!==null)fail('PORTAL_DOCUMENT_PROTOTYPE_FORBIDDEN');
      if(Object.getOwnPropertySymbols(value).length)fail();
      const output=Object.create(null);
      for(const [name,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))){
        if(!descriptor.enumerable)continue;
        if(forbiddenNames.has(name)||!Object.hasOwn(descriptor,'value'))fail('PORTAL_DOCUMENT_PROTOTYPE_FORBIDDEN');
        if(['$ref','$dynamicRef','$recursiveRef'].includes(name)&&typeof descriptor.value==='string'&&!descriptor.value.startsWith('#/'))fail('PORTAL_DOCUMENT_EXTERNAL_REF_FORBIDDEN');
        bytes+=Buffer.byteLength(name);if(bytes>MAX_BYTES)fail('PORTAL_DOCUMENT_TOO_LARGE');
        output[name]=clone(descriptor.value,depth+1);
      }
      return output;
    };
    const document=clone(source,0);
    if(Buffer.byteLength(JSON.stringify(document))>MAX_BYTES)fail('PORTAL_DOCUMENT_TOO_LARGE');
    if(!record(document)||!record(document.info)||typeof document.info.title!=='string'||!document.info.title.trim()||typeof document.info.version!=='string'||!record(document.paths))fail();
    const version=typeof document.openapi==='string'&&/^3\.[01]\.\d+$/.test(document.openapi)?document.openapi:document.swagger==='2.0'?'2.0':null;
    if(!version)fail('PORTAL_DOCUMENT_VERSION_UNSUPPORTED');
    const refTarget=(reference:string,root:any):any=>{
      if(!reference.startsWith('#/'))fail('PORTAL_DOCUMENT_EXTERNAL_REF_FORBIDDEN');
      let pointer:string;try{pointer=decodeURIComponent(reference.slice(2));}catch{fail();}
      let target:any=root;
      for(const raw of pointer!.split('/')){if(/~(?![01])/.test(raw))fail();const part=raw.replace(/~1/g,'/').replace(/~0/g,'~');if(target===null||typeof target!=='object'||!Object.hasOwn(target,part))fail('PORTAL_DOCUMENT_REF_NOT_FOUND');target=target[part];}
      return target;
    };
    let operationCount=0,pathVisits=0;
    const countCallbacks=(callbacks:any,trail:Set<object>,depth:number):void=>{
      if(!record(callbacks)||depth>MAX_DEPTH||++pathVisits>MAX_NODES)fail('PORTAL_DOCUMENT_BUDGET_EXCEEDED');
      for(const [name,callback]of Object.entries(callbacks)){
        if(name.startsWith('x-'))continue;
        if(!record(callback))fail();
        if(trail.has(callback))continue;
        trail.add(callback);
        try{
          if(typeof callback.$ref==='string'){countCallbacks({reference:refTarget(callback.$ref,document)},trail,depth+1);continue;}
          for(const [expression,item]of Object.entries(callback)){if(expression.startsWith('x-'))continue;countPathItem(item,trail,depth+1);}
        }finally{trail.delete(callback);}
      }
    };
    const countPathItem=(item:any,trail=new Set<object>(),depth=0):void=>{
      if(!record(item)||depth>MAX_DEPTH||++pathVisits>MAX_NODES)fail('PORTAL_DOCUMENT_BUDGET_EXCEEDED');
      if(trail.has(item))return;
      trail.add(item);
      try{
        if(typeof item.$ref==='string')countPathItem(refTarget(item.$ref,document),trail,depth+1);
        for(const [name,value]of Object.entries(item))if(methods.has(name)){
          if(!record(value)||++operationCount>2000)fail('PORTAL_DOCUMENT_OPERATIONS_EXCEEDED');
          if(value.callbacks!==undefined)countCallbacks(value.callbacks,trail,depth+1);
        }
      }finally{trail.delete(item);}
    };
    for(const [path,item] of Object.entries(document.paths)){if(path.startsWith('x-'))continue;if(!path.startsWith('/'))fail();countPathItem(item);}
    if(document.webhooks!==undefined){if(!record(document.webhooks))fail();for(const item of Object.values(document.webhooks))countPathItem(item);}
    if(document.components?.pathItems!==undefined){if(!record(document.components.pathItems))fail();for(const item of Object.values(document.components.pathItems))countPathItem(item);}
    if(document.components?.callbacks!==undefined)countCallbacks(document.components.callbacks,new Set<object>(),0);
    let redactedExampleCount=0;
    const references:string[]=[],secretTargets=new WeakSet<object>(),privateVisited=new WeakSet<object>(),targetQueue:object[]=[];
    const sensitive=(name:string,value:unknown='synthetic-document-field'):boolean=>{
      const masked=this.secrets.redact({[name]:value})[name];return typeof masked==='string'&&masked.startsWith('[REDACTED');
    };
    const sample=(value:any):any=>{
      if(typeof value==='string'){const masked=this.secrets.redact(value);if(typeof masked==='string'&&masked.startsWith('[REDACTED')){redactedExampleCount++;return undefined;}return value;}
      if(value===null||typeof value!=='object')return value;
      if(Array.isArray(value))return value.map(child=>sample(child)).filter(child=>child!==undefined);
      const output=Object.create(null);
      for(const [name,child]of Object.entries(value)){if(child!==null&&sensitive(name,typeof child==='boolean'?child:'synthetic-document-field')){redactedExampleCount++;continue;}const clean=sample(child);if(clean!==undefined)output[name]=clean;}
      return output;
    };
    const visit=(value:any,schema=false,secret=false,mapKind='',discover=false):any=>{
      if(value===null||typeof value!=='object')return value;
      if(Array.isArray(value))return value.map(child=>visit(child,schema,secret,'',discover));
      const output=Object.create(null);
      const localSecret=secret||secretTargets.has(value)||value.format==='password'||value.writeOnly===true||value['x-sensitive']===true||(typeof value.name==='string'&&sensitive(value.name,value.type==='boolean'?false:undefined));
      if(discover&&localSecret){if(privateVisited.has(value))return output;privateVisited.add(value);}
      for(const [name,child]of Object.entries(value)){
        if(mapKind==='properties'||mapKind==='schemas'){output[name]=visit(child,true,localSecret||sensitive(name,record(child)&&child.type==='boolean'?false:undefined),'',discover);continue;}
        // Dictionary entry names are descriptors (not example/default values).
        // In particular responses.default may contain a full credential schema.
        if(mapKind==='descriptors'){output[name]=visit(child,false,localSecret||sensitive(name),'',discover);continue;}
        if(['$ref','$dynamicRef','$recursiveRef'].includes(name)){
          if(typeof child!=='string'||!child.startsWith('#/'))fail('PORTAL_DOCUMENT_EXTERNAL_REF_FORBIDDEN');
          const target=refTarget(child,document);references.push(child);
          if(discover&&localSecret&&typeof target==='object'&&target!==null){if(!record(target))fail();if(!secretTargets.has(target)){secretTargets.add(target);targetQueue.push(target);}}
          else if(discover&&localSecret&&typeof target!=='boolean')fail('PORTAL_DOCUMENT_SENSITIVE_REF_INVALID');
          output[name]=child;continue;
        }
        if(!schema&&name==='servers')continue;
        if(['default','example','examples','enum','const'].includes(name)&&mapKind!=='properties'&&mapKind!=='schemas'){
          if(localSecret){redactedExampleCount++;continue;}
          const clean=sample(child);if(clean!==undefined)output[name]=clean;continue;
        }
        if(name==='properties'){output[name]=visit(child,true,localSecret,'properties',discover);continue;}
        if(name==='definitions'||name==='schemas'&&record(value)&&!schema){output[name]=visit(child,true,localSecret,'schemas',discover);continue;}
        if(!schema&&['responses','parameters','headers','content','requestBodies','securitySchemes','links','callbacks','pathItems'].includes(name)&&record(child)){output[name]=visit(child,false,localSecret,'descriptors',discover);continue;}
        const childSchema=name==='schema'||schema&&['items','additionalProperties','not','if','then','else','allOf','anyOf','oneOf','prefixItems'].includes(name);
        output[name]=visit(child,childSchema,localSecret,'',discover);
      }
      return output;
    };
    // Discover tainted reference targets once per private node. This is bounded
    // graph work, not repeated whole-document fixed-point reserialization.
    visit(document,false,false,'',true);
    for(let index=0;index<targetQueue.length;index++)visit(targetQueue[index],true,true,'',true);
    redactedExampleCount=0;references.length=0;
    const clean=visit(document);
    let origin:URL|null=null;
    if(publicProxyOrigin!==null){try{origin=new URL(publicProxyOrigin);if(!['http:','https:'].includes(origin.protocol)||origin.username||origin.password||origin.search||origin.hash||origin.pathname!=='/')fail('PORTAL_PUBLIC_PROXY_ORIGIN_INVALID');}catch(error){if(error instanceof BadRequestException)throw error;fail('PORTAL_PUBLIC_PROXY_ORIGIN_INVALID');}}
    if(version==='2.0'){delete clean.host;delete clean.basePath;delete clean.schemes;if(origin){clean.host=origin.host;clean.basePath='/';clean.schemes=[origin.protocol.slice(0,-1)];}}
    else if(origin)clean.servers=[{url:origin.origin}];
    for(const reference of references)refTarget(reference,clean);
    return {document:clean,hash:this.secrets.fingerprint({kind:'portal-document:v1',document:clean}),report:{version,operationCount,nodeCount:nodes,redactedExampleCount,controlledPublicServer:Boolean(origin),externalReferences:false}};
  }

  markdown(input:string):string {
    if(typeof input!=='string'||Buffer.byteLength(input)>256*1024)fail('PORTAL_MARKDOWN_TOO_LARGE');
    const compact=decodeEntities(input).replace(/[\u0000-\u0020]/g,'');
    if(unsafeText(input)||/(?:javascript|vbscript|data):/i.test(compact))fail('PORTAL_MARKDOWN_UNSAFE');
    const definitions=new Map<string,string>();
    for(const match of input.matchAll(/^\s*\[([^\]]+)\]:\s*<?([^\s>]+)/gm))definitions.set(match[1].toLowerCase(),match[2]);
    const remote=(url:string):boolean=>/^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(decodeEntities(url).replace(/\\/g,'/').replace(/[\u0000-\u0020]/g,''));
    for(const match of input.matchAll(/!\[([^\]]*)\](?:\(\s*<?([^\s)>]+)[^)]*\)|\[([^\]]*)\])?/g)){
      const url=match[2]||definitions.get((match[3]||match[1]).toLowerCase());
      if(!url||remote(url))fail('PORTAL_MARKDOWN_REMOTE_IMAGE_FORBIDDEN');
    }
    const masked=this.secrets.redact(input);if(typeof masked==='string'&&masked.startsWith('[REDACTED'))fail('PORTAL_MARKDOWN_UNSAFE');
    return input.replace(/\r\n?/g,'\n');
  }
}

import {describe,expect,it} from 'vitest';
import {spawn} from 'node:child_process';
import {resolve} from 'node:path';
import {performance} from 'node:perf_hooks';
import {boundedPcre1Matches,PCRE1_PROFILE} from '../../apps/console-api/src/modules/toolbox/pcre1-engine';

const examples:Array<{name:string;pattern:string;yes:string;no:string}>=[
 {name:'atomic alternative does not backtrack',pattern:'/a(?>b|bc)c$',yes:'/abc',no:'/abcc'},
 {name:'possessive quantifier does not backtrack',pattern:'/a++b$',yes:'/aaab',no:'/aaaa'},
 {name:'named backreference',pattern:'/(?<word>[a-z]+)-\\k<word>$',yes:'/same-same',no:'/same-other'},
 {name:'fixed-width lookbehind',pattern:'/prefix/(?<=prefix/)suffix$',yes:'/prefix/suffix',no:'/other/suffix'},
 {name:'branch reset retains first capture numbering',pattern:'/(?|(a)|(b))\\1$',yes:'/bb',no:'/ba'},
 {name:'capture-dependent condition',pattern:'/(a)?(?(1)b|c)$',yes:'/ab',no:'/ac'},
 {name:'named recursive subroutine',pattern:'/(?<node>a(?&node)?b)$',yes:'/aaabbb',no:'/aabbb'},
 {name:'DEFINE subroutine',pattern:'/(?(DEFINE)(?<number>\\d+))(?&number)-(?&number)$',yes:'/12-34',no:'/12-ab'},
 {name:'literal quoting',pattern:'/\\Q[literal].*\\E$',yes:'/[literal].*',no:'/anything'},
 {name:'reset match start',pattern:'/prefix\\Ksuffix$',yes:'/prefixsuffix',no:'/suffix'},
 {name:'inline case folding',pattern:'/(?i)version$',yes:'/VERSION',no:'/VERSION2'},
 {name:'negative lookahead',pattern:'/v1/(?!private)[a-z]+$',yes:'/v1/public',no:'/v1/private'},
 {name:'PCRE hex scalar syntax',pattern:'/\\x{41}+$',yes:'/AAA',no:'/BBB'},
 {name:'PCRE end-of-subject anchor',pattern:'/a\\z',yes:'/a',no:'/ab'},
];
describe('Actual pinned PCRE1 native process, not a JS regex fixture',()=>{
 it.each(examples)('$name matches and rejects with anchored PCRE semantics',async({pattern,yes,no})=>{
  const positive=(await boundedPcre1Matches([pattern],yes))[pattern],negative=(await boundedPcre1Matches([pattern],no))[pattern];
  expect(positive,'native positive result: '+JSON.stringify(positive)).toEqual({match:true});
  expect(negative,'native negative result: '+JSON.stringify(negative)).toEqual({match:false});
 });
 it('anchors every branch without rewriting inline options or wrapping the source',async()=>{
  const pattern='/first|/second';expect((await boundedPcre1Matches([pattern],'/second'))[pattern]).toEqual({match:true});expect((await boundedPcre1Matches([pattern],'/prefix/second'))[pattern]).toEqual({match:false});
 });
 it('reproduces the actual Kong1.5 uri_postfix extension and refuses its duplicate capture name',async()=>{
  const pattern='/(?<uri_postfix>abc)';expect((await boundedPcre1Matches([pattern],'/abc'))[pattern]).toEqual({unsupported:true,reason:'PCRE_COMPILE_ERROR'});
 });
 it('keeps invalid variable-length lookbehind distinct from a real negative match',async()=>{
  const pattern='/(?<=a+)b';expect((await boundedPcre1Matches([pattern],'/b'))[pattern]).toEqual({unsupported:true,reason:'PCRE_COMPILE_ERROR'});
 });
 it('enforces PCRE match limits before catastrophic backtracking can monopolize the API',async()=>{
  const pattern='/(a+)+$',start=performance.now();expect((await boundedPcre1Matches([pattern],'/'+'a'.repeat(3500)+'!'))[pattern]).toEqual({unsupported:true,reason:'PCRE_MATCH_LIMIT'});expect(performance.now()-start).toBeLessThan(1000);
 });
 it('does not interpret pattern contents as a shell command, filename or executable argument',async()=>{
  const pattern='/\\Q$(id);`whoami`|/etc/passwd\\E$';expect((await boundedPcre1Matches([pattern],'/$'+'(id);`whoami`|/etc/passwd'))[pattern]).toEqual({match:true});
 });
 it('uses UTF-8 byte length limits before crossing the native input boundary',async()=>{
  const pattern='/'+'π'.repeat(1024);expect((await boundedPcre1Matches([pattern],'/'))[pattern]).toEqual({unsupported:true,reason:'PCRE_PATTERN_BUDGET'});
  expect((await boundedPcre1Matches(['/x'],'x'.repeat(8193)))['/x']).toEqual({unsupported:true,reason:'PCRE_SUBJECT_BUDGET'});
 });
 it('keeps prototype-like names as own result data without modifying Object.prototype',async()=>{
  const patterns=['__proto__','constructor','/x'];const result=await boundedPcre1Matches(patterns,'/x');expect(Object.getPrototypeOf(result)).toBeNull();expect(Object.hasOwn(result,'__proto__')).toBe(true);expect(result['/x']).toEqual({match:true});expect(({} as any).unsupported).toBeUndefined();
 });
 it('returns an explicit partial result for an already expired caller budget',async()=>{
  expect((await boundedPcre1Matches(['/x'],'/x',0))['/x']).toEqual({unsupported:true,reason:'PCRE_DEADLINE_EXCEEDED'});
 });
 it('advertises all independent, fixed diagnostic budgets',()=>{
  expect(PCRE1_PROFILE).toMatchObject({version:'8.45',jit:false,anchored:true,patternLimit:64,patternBytes:2048,subjectBytes:8192,matchLimit:100000,recursionLimit:256,nativeWallMs:200,parentWallMs:250,memoryBytes:64*1024*1024,concurrency:4});
 });
 it.each([Buffer.from('bad'),Buffer.concat([Buffer.from('KPPCRE1\0'),Buffer.from([0,0,0,2,0,0,0,0,0,0,0,0])]),Buffer.concat([Buffer.from('KPPCRE1\0'),Buffer.from([0,0,0,1,0,0,0,65,0,0,0,0])])])('rejects malformed framed input without parsing JSON or emitting an accepted result',async frame=>{
  const helper=resolve('apps/console-api/native-bin/kongpilot-pcre1');const child=spawn(helper,[],{env:{LANG:'C'},stdio:['pipe','pipe','pipe']});const chunks:Buffer[]=[];child.stdout.on('data',x=>chunks.push(x));const code=await new Promise<number|null>((done,reject)=>{child.once('error',reject);child.once('close',done);child.stdin.end(frame);});expect(code).toBe(64);expect(Buffer.concat(chunks)).toHaveLength(0);
 });
});

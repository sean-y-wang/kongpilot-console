#!/usr/bin/env python3
"""Actual native child/seccomp tests. No Docker, Kong, HTTP, npm install or shell.
Requires fixed PCRE8.45 archive (build cache) and Linux cc. Production source is
included unchanged by tiny test-only translation units; hooks never ship in the
production builder. Optional baseline must match the frozen pre-hardening source.
"""
import argparse,fcntl,hashlib,json,os,resource,shutil,signal,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
P=argparse.ArgumentParser(add_help=False);P.add_argument('--archive',required=True);P.add_argument('--baseline-source');P.add_argument('--report-file');args,remaining=P.parse_known_args();sys.argv=[sys.argv[0],*remaining]
ARCHIVE=Path(args.archive).resolve();BASELINE=Path(args.baseline_source).resolve() if args.baseline_source else None
ARCHIVE_SHA='4e6ce03e0336e8b4a3d6c2b70b1c5e18590a5673a98186da90d4f33c23defc09'
BASELINE_SHA='85ba4c007b56bfc4223ff28ec49cb3ba2d9642c1b2b8e16fecf1ef678c7b926c'
UNITS=['pcre_byte_order.c','pcre_chartables.c','pcre_compile.c','pcre_config.c','pcre_dfa_exec.c','pcre_exec.c','pcre_fullinfo.c','pcre_get.c','pcre_globals.c','pcre_jit_compile.c','pcre_maketables.c','pcre_newline.c','pcre_ord2utf8.c','pcre_refcount.c','pcre_string_utils.c','pcre_study.c','pcre_tables.c','pcre_ucd.c','pcre_valid_utf8.c','pcre_version.c','pcre_xclass.c']
FLAGS=['-O2','-fstack-protector-strong','-fPIE','-pie','-Wl,-z,relro,-z,now,-z,noexecstack','-DHAVE_CONFIG_H','-DPCRE_STATIC','-DSUPPORT_PCRE8','-DSUPPORT_UTF','-DSUPPORT_UCP','-DNO_RECURSE','-DHAVE_STDINT_H','-DHAVE_STDLIB_H','-DHAVE_STRING_H','-DHAVE_MEMMOVE','-DHAVE_UNISTD_H','-DHAVE_LIMITS_H']
ENV={'PATH':'/usr/bin:/bin','LANG':'C'}
NODE=shutil.which('node')
if not NODE:raise RuntimeError('EXISTING_NODE_REQUIRED')
def checked(cmd,**kw):
 r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,timeout=120,**kw)
 if r.returncode:raise RuntimeError('NATIVE_TEST_COMPILATION_FAILED:'+r.stderr.decode(errors='replace')[:2000])
 return r
class NativeSandbox(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if not sys.platform.startswith('linux'):raise unittest.SkipTest('Linux seccomp required')
  if hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()!=ARCHIVE_SHA:raise RuntimeError('FIXED_ARCHIVE_SHA_REQUIRED')
  if BASELINE and hashlib.sha256(BASELINE.read_bytes()).hexdigest()!=BASELINE_SHA:raise RuntimeError('FIXED_BASELINE_SHA_REQUIRED')
  cls.temp=tempfile.TemporaryDirectory(prefix='kp-pcre-sandbox-test-');cls.work=Path(cls.temp.name);cls.binaries={}
  unpack="import{unpackPcre1}from"+json.dumps(str(ROOT/'deploy/scripts/prepare-pcre1-engine.mjs'))+";import{readFileSync,writeFileSync}from'node:fs';import{join}from'node:path';for(const[n,b]of unpackPcre1(readFileSync(process.argv[1])))writeFileSync(join(process.argv[2],n),b,{mode:384});"
  checked([NODE,'--input-type=module','-e',unpack,str(ARCHIVE),str(cls.work)])
  for a,b in [('config.h.generic','config.h'),('pcre.h.generic','pcre.h'),('pcre_chartables.c.dist','pcre_chartables.c')]: (cls.work/b).write_bytes((cls.work/a).read_bytes())
  checked(['/usr/bin/cc',*FLAGS,'-I'+str(cls.work),'-c',*[str(cls.work/u) for u in UNITS]],cwd=cls.work)
  source=ROOT/'apps/console-api/native/pcre1/engine.c'
  cls.compile('production',None,source)
  def body(expression):return 'sandbox();'+expression+';stop(73);return 73;'
  # Source-level static functions are exercised verbatim; no production hook.
  cls.compile('close-range','if(fcntl(4096,F_GETFD)<0)stop(72);close_inherited_descriptors();if(fcntl(4096,F_GETFD)>=0||errno!=EBADF)stop(71);stop(0);',source)
  cls.compile('close-fallback','if(fcntl(4096,F_GETFD)<0)stop(72);close_inherited_descriptors_fallback();if(fcntl(4096,F_GETFD)>=0||errno!=EBADF)stop(71);stop(0);',source)
  cls.compile('fallback-budget','close_inherited_descriptors_fallback();stop(71);',source)
  file_map=body('void *p=mmap(NULL,4096,PROT_READ,MAP_PRIVATE,0,0);if(p==MAP_FAILED)stop(74);if(write(1,p,1)!=1)stop(75)')
  cls.compile('file-map',file_map,source)
  if BASELINE:cls.compile('baseline-file-map',file_map,BASELINE)
  cls.compile('anon-map',body("unsigned char *p=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED)stop(74);p[0]='K';if(write(1,p,1)!=1)stop(75);stop(0)"),source)
  cls.compile('exec-map',body('mmap(NULL,4096,PROT_READ|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0)'),source)
  cls.compile('exec-mprotect','void *p=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED)stop(74);sandbox();mprotect(p,4096,PROT_READ|PROT_EXEC);stop(73);',source)
  for name,call in [('open','syscall(__NR_openat,AT_FDCWD,"/etc/passwd",O_RDONLY,0)'),('socket','syscall(__NR_socket,2,1,0)'),('ptrace','syscall(__NR_ptrace,0,0,0,0)'),('exec','syscall(__NR_execve,"/bin/true",NULL,NULL)')]:cls.compile(name,body(call),source)
 @classmethod
 def compile(cls,name,body,source):
  target=cls.work/name
  if body is None:unit=source
  else:
   unit=cls.work/(name+'.c');unit.write_text('#define main kongpilot_original_main\n#include '+json.dumps(str(source))+'\n#undef main\nint main(void){'+body+'return 0;}\n')
  checked(['/usr/bin/cc',*FLAGS,'-I'+str(cls.work),str(unit),*[str(cls.work/u.replace('.c','.o')) for u in UNITS],'-o',str(target)],cwd=cls.work);cls.binaries[name]=target
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def child(self,name,**kw):return subprocess.run([str(self.binaries[name])],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2,**kw)
 def test_actual_high_fd_4096_is_closed_by_close_range(self):self.high_fd('close-range',False)
 def test_actual_high_fd_4096_is_closed_by_bounded_proc_fallback(self):self.high_fd('close-fallback',False)
 def test_fd_above_lowered_current_nofile_is_closed_by_close_range(self):self.high_fd('close-range',True)
 def test_fd_above_lowered_current_nofile_is_closed_by_proc_fallback(self):self.high_fd('close-fallback',True)
 def high_fd(self,name,lower):
  with open('/dev/null','rb') as f:
   fd=fcntl.fcntl(f,fcntl.F_DUPFD,4096)
   try:
    self.assertEqual(fd,4096)
    def limit():resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
    r=self.child(name,pass_fds=(fd,),preexec_fn=limit if lower else None,input=b'');self.assertEqual(r.returncode,0);self.assertEqual(r.stdout,b'')
   finally:os.close(fd)
 def test_fallback_excessive_fd_count_fails_closed_with_fixed_budget(self):
  descriptors=[]
  try:
   for _ in range(4097):descriptors.append(os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC))
   r=self.child('fallback-budget',pass_fds=tuple(descriptors),input=b'');self.assertEqual(r.returncode,70);self.assertEqual(r.stdout,b'')
  finally:
   for fd in descriptors:os.close(fd)
 def test_file_backed_nonexec_mmap_of_live_stdin_is_killed(self):
  with tempfile.TemporaryFile() as f:
   f.write(b'K'+b'\0'*4095);f.flush();f.seek(0);r=self.child('file-map',stdin=f)
  self.assertEqual(r.returncode,-signal.SIGSYS);self.assertEqual(r.stdout,b'')
 def test_anonymous_nonexec_mmap_remains_available_for_real_allocator(self):
  r=self.child('anon-map',input=b'');self.assertEqual(r.returncode,0);self.assertEqual(r.stdout,b'K')
 def test_optional_frozen_baseline_actually_allowed_the_file_mapping(self):
  if not BASELINE:self.skipTest('Optional historical regression control not supplied')
  with tempfile.TemporaryFile() as f:
   f.write(b'K'+b'\0'*4095);f.flush();f.seek(0);r=self.child('baseline-file-map',stdin=f)
  self.assertEqual(r.returncode,73);self.assertEqual(r.stdout,b'K')
 def test_executable_mmap_is_killed(self):self.assert_denied('exec-map')
 def test_executable_mprotect_is_killed(self):self.assert_denied('exec-mprotect')
 def test_openat_is_killed(self):self.assert_denied('open')
 def test_socket_is_killed(self):self.assert_denied('socket')
 def test_execve_is_killed(self):self.assert_denied('exec')
 def test_ptrace_is_killed(self):self.assert_denied('ptrace')
 def assert_denied(self,name):
  r=self.child(name,input=b'');self.assertEqual(r.returncode,-signal.SIGSYS);self.assertEqual(r.stdout,b'')
 def test_production_child_matches_real_atomic_PCRE_under_new_sandbox(self):
  self.match('/a(?>b|bc)c$','/abc',1);self.match('/a(?>b|bc)c$','/abcc',0)
 def test_production_child_retains_real_PCRE_catastrophic_match_limit(self):self.match('/(a+)+$','/'+'a'*3500+'!',3)
 def match(self,pattern,subject,status):
  p=pattern.encode();s=subject.encode();frame=b'KPPCRE1\0'+(1).to_bytes(4,'big')+(1).to_bytes(4,'big')+len(s).to_bytes(4,'big')+s+len(p).to_bytes(4,'big')+p
  r=self.child('production',input=frame);self.assertEqual(r.returncode,0);self.assertEqual(r.stdout,b'KPPCR01\0'+(1).to_bytes(4,'big')+(1).to_bytes(4,'big')+bytes([status]))
if not BASELINE:delattr(NativeSandbox,'test_optional_frozen_baseline_actually_allowed_the_file_mapping')
if __name__=='__main__':
 program=unittest.main(verbosity=2,exit=False);r=program.result
 summary={'format':'kongpilot-pcre1-native-sandbox-tests-v1','completed':True,'tests':r.testsRun,'passed':r.testsRun-len(r.failures)-len(r.errors)-len(r.skipped),'failed':len(r.failures),'errors':len(r.errors),'skipped':len(r.skipped),'actualExit':0 if r.wasSuccessful() and not r.skipped else 1,'kongContacted':False,'baselineControlIncluded':BASELINE is not None}
 if args.report_file:
  report=Path(args.report_file)
  if not report.is_absolute():raise RuntimeError('ABSOLUTE_NEW_REPORT_REQUIRED')
  fd=os.open(report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w')as f:f.write(json.dumps(summary,indent=2)+'\n');f.flush();os.fsync(f.fileno())
 sys.exit(summary['actualExit'])

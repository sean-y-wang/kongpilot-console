/* KongPilot PCRE1 diagnostic worker. Linked only with pinned upstream PCRE8.45.
 * No user-selected files, URLs, shell, credentials, JIT or native write authority.
 * Input/output are a versioned, bounded binary protocol over fd0/fd1 only. */
#define _GNU_SOURCE
#include <pcre.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/mman.h>

#if defined(__x86_64__)
#define KP_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define KP_ARCH AUDIT_ARCH_AARCH64
#else
#error Unsupported audit architecture; never run without the syscall filter.
#endif
#define KP_URI_SUFFIX "(?<uri_postfix>.*)"
#define KP_MAX_PATTERNS 64u
#define KP_MAX_PATTERN_BYTES 2048u
#define KP_MAX_SUBJECT_BYTES 8192u
#define KP_MATCH_LIMIT 100000u
#define KP_RECURSION_LIMIT 256u
#define KP_AS_BYTES (64u*1024u*1024u)
#define KP_STACK_BYTES (512u*1024u)
#define ALLOW(nr) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(nr),0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
#define FD_ONLY(nr,fd) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(nr),0,4), BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(fd),0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS)
#define ANON_NONEXEC(nr) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(nr),0,6), BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])), BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,PROT_EXEC,3,0), BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[3])), BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,MAP_ANONYMOUS,0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS)
#define NONEXEC(nr) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(nr),0,4), BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])), BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,PROT_EXEC,1,0), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS)
static unsigned char subject[KP_MAX_SUBJECT_BYTES+1],pattern[KP_MAX_PATTERN_BYTES+sizeof(KP_URI_SUFFIX)],result[16+KP_MAX_PATTERNS];
static const unsigned char input_magic[8]={'K','P','P','C','R','E','1',0};
static const unsigned char output_magic[8]={'K','P','P','C','R','0','1',0};
static void stop(int code){_exit(code);}
static void limit(int resource,rlim_t value){struct rlimit r={value,value};if(setrlimit(resource,&r))stop(70);}
/* close_range covers inherited descriptors above a caller-lowered NOFILE limit.
 * Old kernels/outer syscall policies use one bounded /proc/self/fd traversal.
 * It allocates no new descriptors while traversing, closes every observed
 * descriptor except its own directory and fd0..2, and requires actual EOF.
 * An unavailable /proc or excessive descriptor count fails closed. */
struct kp_linux_dirent64 {uint64_t ino;int64_t off;unsigned short reclen;unsigned char type;char name[];};
static void close_inherited_descriptors_fallback(void){
 int directory=open("/proc/self/fd",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(directory<0)stop(70);
 _Alignas(struct kp_linux_dirent64) unsigned char bytes[4096];unsigned int batches=0,entries=0;
 for(;;){
  if(++batches>64)stop(70);
  long n=syscall(__NR_getdents64,directory,bytes,sizeof(bytes));if(n<0)stop(70);if(n==0)break;
  if((unsigned long)n>sizeof(bytes))stop(70);
  for(size_t at=0;at<(size_t)n;){
   struct kp_linux_dirent64 *d=(struct kp_linux_dirent64 *)(bytes+at);
   size_t minimum=offsetof(struct kp_linux_dirent64,name)+1;
   if((size_t)n-at<minimum||d->reclen<minimum||d->reclen%sizeof(uint64_t)||d->reclen>(size_t)n-at||!memchr(d->name,0,d->reclen-(minimum-1)))stop(70);
   if(++entries>4096)stop(70);
   if(strcmp(d->name,".")&&strcmp(d->name,"..")){
    unsigned int fd=0;const unsigned char *digit=(const unsigned char *)d->name;if(!*digit)stop(70);
    for(;*digit;digit++){if(*digit<'0'||*digit>'9'||fd>((unsigned int)INT_MAX-(*digit-'0'))/10)stop(70);fd=fd*10+(*digit-'0');}
    if(fd>=3&&(int)fd!=directory&&close((int)fd)<0&&errno!=EBADF&&errno!=EINTR)stop(70);
   }
   at+=d->reclen;
  }
 }
 if(close(directory)<0&&errno!=EINTR)stop(70);
}
static void close_inherited_descriptors(void){
 if(syscall(__NR_close_range,3u,~0u,0u)==0)return;
 if(errno!=ENOSYS&&errno!=EINVAL&&errno!=EPERM)stop(70);
 close_inherited_descriptors_fallback();
}
static void sandbox(void){
 struct itimerval wall={{0,0},{0,200000}};if(setitimer(ITIMER_REAL,&wall,NULL))stop(70);
 close_inherited_descriptors();
 limit(RLIMIT_CORE,0);limit(RLIMIT_FSIZE,0);limit(RLIMIT_NOFILE,3);
 limit(RLIMIT_CPU,1);limit(RLIMIT_AS,KP_AS_BYTES);limit(RLIMIT_STACK,KP_STACK_BYTES);
 if(prctl(PR_SET_DUMPABLE,0,0,0,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))stop(70);
 struct sock_filter code[]={
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
  BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,KP_ARCH,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
  FD_ONLY(__NR_read,0),FD_ONLY(__NR_write,1),
  ALLOW(__NR_exit),ALLOW(__NR_exit_group),ALLOW(__NR_brk),ALLOW(__NR_munmap),ALLOW(__NR_mremap),
  ALLOW(__NR_clock_gettime),ALLOW(__NR_getrandom),ANON_NONEXEC(__NR_mmap),NONEXEC(__NR_mprotect),
  BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS)
 };
 struct sock_fprog program={(unsigned short)(sizeof(code)/sizeof(code[0])),code};
 if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program))stop(70);
}
static void read_exact(void *ptr,size_t n){unsigned char *p=ptr;while(n){ssize_t got=read(0,p,n);if(got<0&&errno==EINTR)continue;if(got<=0)stop(64);p+=got;n-=(size_t)got;}}
static uint32_t u32(void){unsigned char b[4];read_exact(b,4);return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];}
static void put_u32(unsigned char *p,uint32_t n){p[0]=(unsigned char)(n>>24);p[1]=(unsigned char)(n>>16);p[2]=(unsigned char)(n>>8);p[3]=(unsigned char)n;}
static unsigned char match_pattern(const unsigned char *expression,int length){
 const char *error=NULL;int error_at=0;
 pcre *compiled=pcre_compile((const char *)expression,PCRE_ANCHORED,&error,&error_at,NULL);
 if(!compiled)return 2;
 pcre_extra bounded;memset(&bounded,0,sizeof(bounded));bounded.flags=PCRE_EXTRA_MATCH_LIMIT|PCRE_EXTRA_MATCH_LIMIT_RECURSION;bounded.match_limit=KP_MATCH_LIMIT;bounded.match_limit_recursion=KP_RECURSION_LIMIT;
 int offsets[3];int code=pcre_exec(compiled,&bounded,(const char *)subject,length,0,0,offsets,3);pcre_free(compiled);
 return code>=0?1:code==PCRE_ERROR_NOMATCH?0:(code==PCRE_ERROR_MATCHLIMIT||code==PCRE_ERROR_RECURSIONLIMIT)?3:4;
}
int main(void){
 sandbox();
#ifdef KP_TEST_DENIED_SYSCALL
 /* Test-only build: production build flags never define this constant. */
 syscall(KP_TEST_DENIED_SYSCALL,-1,"/proc/self/environ",0,0,0,0);stop(71);
#endif
 unsigned char magic[8];read_exact(magic,8);if(memcmp(magic,input_magic,8)||u32()!=1)stop(64);
 uint32_t count=u32(),length=u32();if(count>KP_MAX_PATTERNS||length>KP_MAX_SUBJECT_BYTES)stop(64);
 read_exact(subject,length);subject[length]=0;
 for(uint32_t i=0;i<count;i++){
  uint32_t size=u32();if(!size||size>KP_MAX_PATTERN_BYTES)stop(64);read_exact(pattern,size);pattern[size]=0;
  if(memchr(pattern,0,size)){result[16+i]=2;continue;}
  /* Kong1.5 first indexes with the original anchored pattern, then runs
   * its exact strip_regex extension in the URI matcher. Do both: recursion,
   * forward references and duplicate uri_postfix names must not be rewritten. */
  result[16+i]=match_pattern(pattern,(int)length);
  if(result[16+i]==1){memcpy(pattern+size,KP_URI_SUFFIX,sizeof(KP_URI_SUFFIX));result[16+i]=match_pattern(pattern,(int)length);}

 }
 unsigned char extra;ssize_t end;do{end=read(0,&extra,1);}while(end<0&&errno==EINTR);if(end!=0)stop(64);
 memcpy(result,output_magic,8);put_u32(result+8,1);put_u32(result+12,count);
 size_t remaining=16+count;const unsigned char *p=result;while(remaining){ssize_t sent=write(1,p,remaining);if(sent<0&&errno==EINTR)continue;if(sent<=0)stop(74);p+=sent;remaining-=(size_t)sent;}
 stop(0);return 0;
}

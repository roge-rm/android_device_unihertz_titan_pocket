#!/usr/bin/env python3
"""Exercise actual RAM UFS helpers with synthetic sysfs/data, never a real device."""
import pocket_paths
import hashlib,json,os,struct,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
HEADER=ROOT/'kernel-upgrade/ram-probe/ufs-readonly.h'
OUT=pocket_paths.build_root() / 'out/ufs-readonly-host'
HARNESS=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <setjmp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <sys/sysmacros.h>
static int fake_identity;
static int test_open(const char *path,int flags) {
 assert((flags&O_ACCMODE)==O_RDONLY && !(flags&(O_CREAT|O_TRUNC|O_APPEND)));
 return open(path,flags);
}
static int test_fstat(int fd,struct stat *s) {
 int result=fstat(fd,s);
 if(!result && fake_identity) {s->st_mode=S_IFBLK|0400;s->st_rdev=makedev(8,fake_identity==2?1:0);}
 return result;
}
static unsigned signal_resets;
static void (*test_signal(int sig,void (*handler)(int)))(int) {
 assert(sig==SIGCHLD && handler==SIG_DFL);signal_resets++;return SIG_IGN;
}
static pid_t test_fork(void);
static pid_t test_waitpid(pid_t,int *,int);
static int test_kill(pid_t,int);
static unsigned test_sleep(unsigned);
static void test_exit(int) __attribute__((noreturn));
#define TPUFS_FSTAT test_fstat
#define open test_open
#define signal test_signal
#define fork test_fork
#define waitpid test_waitpid
#define kill test_kill
#define sleep test_sleep
#define _exit test_exit
#include "HEADER"
#undef open
#undef signal
#undef fork
#undef waitpid
#undef kill
#undef sleep
#undef _exit
static unsigned forks,waits,kills,slept,mode;
static int exited;
static jmp_buf escape;
static void report(const char *s){puts(s);}
static pid_t test_fork(void){forks++;if(mode==0)return 123;if(mode==1)return -1;return forks==1?0:mode==2?-1:456;}
static pid_t test_waitpid(pid_t pid,int *status,int flags){assert(pid==456&&flags==WNOHANG);waits++;if(mode==4){*status=0;return 456;}if(mode==5){errno=ECHILD;return -1;}return 0;}
static int test_kill(pid_t pid,int sig){assert(pid==456&&sig==SIGKILL);kills++;return 0;}
static unsigned test_sleep(unsigned s){slept+=s;return 0;}
static void test_exit(int status){exited=status;longjmp(escape,1);}
static void controls(void){
 for(mode=0;mode<6;mode++){
  forks=waits=kills=slept=signal_resets=0;exited=-1;
  if(!setjmp(escape)){
   int result=tpufs_start("/missing","/missing",1,report);
   assert(mode<2&&result==(mode==1?-1:0));
  }
  if(mode==0)assert(forks==1&&!waits&&!slept&&!kills);
  if(mode==1)assert(forks==1&&!waits&&!slept&&!kills);
  if(mode==2)assert(forks==2&&exited==1&&!waits&&!slept&&!kills);
  if(mode==3)assert(forks==2&&exited==1&&waits==30&&slept==30&&kills==1);
  if(mode==4)assert(exited==0&&waits==1&&!slept&&!kills);
  if(mode==5)assert(exited==1&&waits==1&&!kills&&!slept);
  assert(signal_resets==(mode>=2));
 }
 slept=0;tpufs_worker("/missing","/missing",0,report);assert(slept==20);
}
int main(int argc,char **argv){
 if(argc==1){
  unsigned long long n;dev_t d;struct stat s={.st_mode=S_IFBLK,.st_rdev=makedev(8,0)};
  assert(tpufs_block_identity(&s,makedev(8,0)));assert(!tpufs_block_identity(&s,makedev(8,1)));s.st_mode=S_IFREG;assert(!tpufs_block_identity(&s,makedev(8,0)));
  assert(!tpufs_uint("123\n",&n)&&n==123);assert(tpufs_uint("-1",&n));assert(tpufs_uint("1x",&n));assert(tpufs_uint("18446744073709551616",&n));assert(tpufs_uint("",&n));
  assert(!tpufs_device_number("8:0\n",&d)&&d==makedev(8,0));assert(tpufs_device_number("8:0x",&d));assert(tpufs_device_number("8:-1",&d));assert(tpufs_device_number("4294967296:0",&d));
  assert(tpufs_owned("/sys/devices/platform/11270000.ufshci","/sys/devices/platform/11270000.ufshci/host0/target0/0/block/sda"));
  assert(!tpufs_owned("/sys/devices/platform/11270000.ufshci","/sys/devices/platform/11270000.ufshci-fake/block/sda"));
  assert(!tpufs_owned("/sys/devices/platform/11270000.ufshci","/sys/devices/platform/11270000.ufshci/host0/block/sda/sda1"));
  assert(!tpufs_owned("/sys/devices/platform/11270001.ufshci","/sys/devices/platform/11270001.ufshci/block/sda"));
  assert(tpufs_name("sda")&&!tpufs_name("../sda")&&!tpufs_name(".hidden")&&!tpufs_name("sda/extra")&&!tpufs_name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  struct tpufs_read_result r=tpufs_read_signature(-1);assert(r.bytes==-1&&r.error==EBADF&&!r.gpt&&!r.mbr);
  controls();puts("self checks passed");return 0;
 }
 if(!strcmp(argv[1],"read")){
  int fd=open(argv[2],O_RDONLY);assert(fd>=0);struct tpufs_read_result r=tpufs_read_signature(fd);close(fd);
  printf("%zd %d %d %d\n",r.bytes,r.error,r.mbr,r.gpt);return 0;
 }
 assert(argc==6);fake_identity=atoi(argv[5]);
 if(!strcmp(argv[1],"worker")){slept=0;tpufs_worker(argv[2],argv[3],atoi(argv[4]),report);assert(slept==5);return 0;}
 assert(!strcmp(argv[1],"scan"));
 printf("found=%d\n",tpufs_scan(argv[2],argv[3],atoi(argv[4]),report));return 0;
}
'''

def main():
 OUT.mkdir(parents=True,exist_ok=True)
 source=OUT/'check.c';source.write_text(HARNESS.replace('HEADER',str(HEADER)))
 binary=OUT/'check'
 subprocess.run(['gcc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-pie','-no-pie',str(source),'-o',str(binary)],check=True)
 def run(*args):return subprocess.run([str(binary),*map(str,args)],check=True,capture_output=True,text=True).stdout
 assert 'self checks passed' in run()
 with tempfile.TemporaryDirectory(prefix='tpufs-',dir=OUT) as temporary:
  root=Path(temporary);sysroot=root/'sys';dev=root/'dev';dev.mkdir()
  controller=sysroot/'devices/platform/11270000.ufshci';controller.mkdir(parents=True)
  platform=sysroot/'bus/platform/devices';platform.mkdir(parents=True);(platform/controller.name).symlink_to(controller)
  classes=sysroot/'class/block';classes.mkdir(parents=True)
  def block(name,owner=controller,partition=False):
   p=owner/'host0/target0/0/block'/name;p.mkdir(parents=True)
   (classes/name).symlink_to(p);(p/'dev').write_text('8:0\n');(p/'size').write_text('4096\n')
   (p/'device').mkdir();(p/'device/model').write_bytes(b'Model\x01 name\nPRIVATE_AFTER_NEWLINE')
   if partition:(p/'partition').write_text('1\n')
   return p
  good=block('sda');block('sda1',partition=True)
  block('loop0',sysroot/'devices/virtual');block('ram0',sysroot/'devices/platform/11270000.ufshci-fake')
  block('sdb',sysroot/'devices/platform/11280000.ufshci');(classes/'broken').symlink_to(root/'missing')
  bytes1024=bytearray(2048);bytes1024[510:512]=b'\x55\xaa';bytes1024[512:520]=b'EFI PART';bytes1024[1024:]=b'X'*1024
  data=dev/'sda';data.write_bytes(bytes1024)
  text=run('scan',sysroot,dev,1,1)
  assert 'found=1' in text and 'read_bytes=1024 read_error=0 mbr=1 gpt512=1' in text
  assert 'Model? name' in text and 'PRIVATE' not in text and 'EFI PART' not in text and 'loop0' not in text and 'sda1' not in text and 'ram0' not in text and 'sdb' not in text
  text=run('worker',sysroot,dev,1,1);assert text.count('read_bytes=')==1 and 'scan complete' in text
  assert run('read',dev).strip()=='-1 21 0 0' # actual pread failure, EISDIR
  assert 'no block read' in run('scan',sysroot,dev,1,0) # actual regular file identity rejected
  assert 'no block read' in run('scan',sysroot,dev,1,2) # wrong major/minor rejected
  assert 'read_bytes=' not in run('scan',sysroot,dev,0,1)
  data.unlink();data.symlink_to(root/'missing');assert 'open_error=' in run('scan',sysroot,dev,1,1);data.unlink()
  data.write_bytes(b'SECRET');assert 'read_bytes=6 read_error=0 mbr=0 gpt512=0' in run('scan',sysroot,dev,1,1)
  for size in [0,1,510,511,512,519,520,1023,1024,2048]:
   data.write_bytes(bytes1024[:size]);assert run('read',data).strip()==f'{min(size,1024)} 0 {int(size>=512)} {int(size>=520)}'
  for value in ['-1','0','1x','18446744073709551616','1'*128]:
   (good/'size').write_text(value);assert 'found=0' in run('scan',sysroot,dev,1,1)
  (good/'size').write_text('4096\n')
  for value in ['8:-1','8:0x','4294967296:0','1'*128]:
   (good/'dev').write_text(value);assert 'found=0' in run('scan',sysroot,dev,1,1)
  (good/'dev').write_text('8:0\n');(good/'partition').symlink_to(root/'missing')
  assert 'found=0' in run('scan',sysroot,dev,1,1)
  assert data.read_bytes()==bytes1024 # header never changes contents
 # Build integration-only static ARM64 helper. Parent owns init hook/packaging.
 arm=OUT/'ufs-readonly-arm64.c';arm.write_text('#define _GNU_SOURCE\n#include "'+str(HEADER)+'"\nstatic void log_line(const char *s){dprintf(2,"%s\\n",s);}\nint main(void){if(tpufs_start("/sys","/dev",1,log_line))return 1; while(wait(NULL)>0 || errno==EINTR){} return 0;}\n')
 target=OUT/'ufs-readonly-arm64';clang=str(pocket_paths.ndk_bin() / 'clang')
 subprocess.run([clang,'--target=aarch64-linux-android30','-static','-Os','-Wall','-Wextra','-Werror',str(arm),'-o',str(target)],check=True)
 elf=target.read_bytes();assert elf[:5]==b'\x7fELF\x02' and struct.unpack_from('<HH',elf,16)==(2,183)
 off=struct.unpack_from('<Q',elf,32)[0];width,count=struct.unpack_from('<HH',elf,54)
 assert all(struct.unpack_from('<I',elf,off+i*width)[0]!=3 for i in range(count))
 record={'header_sha256':hashlib.sha256(HEADER.read_bytes()).hexdigest(),'tool_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'host_asan_ubsan_passed':True,'actual_functions_tested':True,'synthetic_identity_shim_explicit':True,'static_arm64_helper':str(target),'static_arm64_sha256':hashlib.sha256(elf).hexdigest(),'read_limit_bytes':1024,'worker_budget_seconds':30,'async_initial_scan_seconds':20,'additional_lun_grace_seconds':5,'phone_accessed':False,'image_packaged':False,'limitations':['Tests use synthetic sysfs/data and a stat shim for positive block identity, never real block devices','Kernel initialization issues configuration commands; only userspace block workload is read-only','Parent must arm independent return timer before invoking tpufs_start','A task stuck in uninterruptible kernel I/O may outlive SIGKILL; PID1 and USB remain independent']}
 (ROOT/'evidence/kernel-upgrade/ufs-readonly-check.json').write_text(json.dumps(record,indent=2)+'\n')
 print('Actual helpers: ownership/partition/node identity, bounded signatures/short reads/errors, six supervisor control paths, scan deadline pass; static ARM64 ELF linked')
if __name__=='__main__':main()

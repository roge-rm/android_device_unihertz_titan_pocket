#!/usr/bin/env python3
"""Host-test the v11 probe helpers added over v9: the userdata restore-on-exit write test
(driven through callbacks against a sparse file, including restore after a simulated failed
write and a check that writes stay inside the region) and the LP (super) metadata parser
(against the first 1 MiB of the stock super image). Also checks the read-only rule in the
v11 init source: the only writable open is the userdata node. ASan/UBSan, synthetic or
stock-image data only; never accesses a phone."""
import hashlib,json,os,re,struct,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
HEADER=ROOT/'kernel-upgrade/diagnostic-probe-v11/probes.h'
INIT=ROOT/'kernel-upgrade/diagnostic-probe-v11/init.c'
SUPER=ROOT/'firmware/installed-20230105/super.raw.img'
TOOL=ROOT/'tools/pocket-partition-hashes.py'
KERNEL_DM_HEADER=ROOT/'tools/kernel-source/upgrade-5.10/include/uapi/linux/dm-ioctl.h'
KERNEL_DM_C=ROOT/'tools/kernel-source/upgrade-5.10/drivers/md/dm-ioctl.c'

C_TEST=r'''
#include "probes.h"
#include <assert.h>
static FILE *out;
static void report(const char *m){fprintf(out,"%s\n",m);}
// Write-test ops over a file. Every offset is relative to the region base, as init does.
// fail_on_write injects an EIO on the Nth pwrite, to exercise restore after a failed write.
struct fctx{int fd;unsigned long long base;int fail_on_write;int writes;};
static ssize_t f_pread(void *c,void *b,size_t n,uint64_t off){struct fctx *x=c;return pread(x->fd,b,n,(off_t)(x->base+off));}
static ssize_t f_pwrite(void *c,const void *b,size_t n,uint64_t off,int fua){struct fctx *x=c;(void)fua;++x->writes;
 if(x->fail_on_write&&x->writes==x->fail_on_write){errno=EIO;return -1;}return pwrite(x->fd,b,n,(off_t)(x->base+off));}
static int f_sync(void *c){return fdatasync(((struct fctx*)c)->fd);}
static void run_write(const char *name,const char *path,unsigned long long base,size_t region,int fail_on_write){
 int fd=open(path,O_RDWR);assert(fd>=0);
 struct fctx cx={fd,base,fail_on_write,0};
 static const struct tp10_write_ops ops={f_pread,f_pwrite,f_sync};
 fprintf(out,"write-begin %s\n",name);
 struct tp10_write_result r=tp10_write_test(&ops,&cx,region,base/512,report);
 fprintf(out,"write-result %s step1=%d step2=%d step3=%d restore_attempted=%d restore=%d bytes=%llu budget=%llu orig=%s writes=%d\n",
  name,r.step1_ok,r.step2_ok,r.step3_ok,r.restore_attempted,r.restore_ok,(unsigned long long)r.bytes_written,(unsigned long long)r.budget,r.original_sha256,cx.writes);
 fsync(fd);close(fd);}
int main(int argc,char **argv){
 assert(argc==4);
 out=fopen(argv[1],"w");assert(out);
 size_t region=1u<<20;
 // Userdata write test: the last 1 MiB of a 3 MiB file is the region; base 2 MiB.
 run_write("clean",argv[2],2ull<<20,region,0);      // all four steps succeed
 run_write("fail2",argv[2],2ull<<20,region,1);      // step 2 write fails; restore still runs
 run_write("fail3",argv[2],2ull<<20,region,2);      // step 3 write fails; restore still runs
 // LP parser against the first 1 MiB of the stock super image.
 int fd=open(argv[3],O_RDONLY);assert(fd>=0);
 static unsigned char buf[1u<<20];
 ssize_t n=read(fd,buf,sizeof(buf));close(fd);assert(n==(ssize_t)sizeof(buf));
 struct tp10_lp lp;const char *why="";
 int count=tp10_lp_parse(buf,sizeof(buf),&lp,&why);
 fprintf(out,"lp count=%d why=%s lbs=%u first_logical_sector=%llu device_size=%llu\n",
  count,why,lp.logical_block_size,(unsigned long long)lp.first_logical_sector,(unsigned long long)lp.device_size);
 for(unsigned i=0;i<lp.num_partitions;++i){struct tp10_lp_partition *p=&lp.partitions[i];
  fprintf(out,"lp-part %s group=%u extents=%u sectors=%llu\n",p->name,p->group_index,p->num_extents,(unsigned long long)p->sectors);
  for(unsigned x=0;x<p->num_extents;++x)fprintf(out,"lp-extent %s %u num=%llu target=%llu\n",p->name,x,
   (unsigned long long)p->extents[x].num_sectors,(unsigned long long)p->extents[x].target_sector);}
 // Negative: a flipped byte in the geometry, header and tables each fails its checksum.
 struct tp10_lp bad;
 for(int k=0;k<3;++k){unsigned off=(k==0)?(4096+44):(k==1)?(12288+8):(12288+128+4);
  unsigned char save=buf[off];buf[off]^=1;
  fprintf(out,"lp-bad %d %d\n",k,tp10_lp_parse(buf,sizeof(buf),&bad,&why));fprintf(out,"lp-bad-why %d %s\n",k,why);buf[off]=save;}
 // Negative: a truncated buffer returns short_buffer, not a crash.
 fprintf(out,"lp-short %d\n",tp10_lp_parse(buf,4096,&bad,&why));
 // Touchpad reset sequence constants and the shared i2c result line.
 fprintf(out,"pad gpio=%d steps=%zu",TP11_PAD_RESET_GPIO,(size_t)TP11_PAD_STEPS);
 for(size_t i=0;i<TP11_PAD_STEPS;++i)fprintf(out," %d:%u",tp11_pad_steps[i].value,tp11_pad_steps[i].wait_us);
 fprintf(out," gap=%u sleep_us=%u\n",TP11_PAD_RETRY_GAP_US,(unsigned)TP11_PAD_SLEEP_US);
 fprintf(out,"pad-need nack_nack=%d ok_nack=%d nack_ok=%d timeout_nack=%d\n",tp11_pad_needs_reset(ENXIO,ENXIO),tp11_pad_needs_reset(0,ENXIO),tp11_pad_needs_reset(ENXIO,0),tp11_pad_needs_reset(ETIMEDOUT,ENXIO));
 { const struct tp8_i2c_target *t=&tp8_i2c_targets[4];char line[240];unsigned char d[8]={0x01,0x02,0x03,0x04,0x05,0x06};
   tp11_i2c_line(line,sizeof(line),t,3,2,0,d,"none",12.4," reset=pulsed");fprintf(out,"%s\n",line);
   tp11_i2c_line(line,sizeof(line),&tp8_i2c_targets[5],3,-1,ENXIO,d,"none",1.6," reset=pulsed");fprintf(out,"%s\n",line);
   tp11_i2c_line(line,sizeof(line),&tp8_i2c_targets[6],4,2,0,d,"none",3,"");fprintf(out,"%s\n",line);}
 fclose(out);return 0;}
'''

# Host test of the dm-ioctl builders. The kernel's own 5.10 uapi dm-ioctl.h is used for the
# structs and version (copied into a temp include dir so the host's <linux/dm-ioctl.h> is not
# used). check_version, next_target, invalid_str and populate_table's walk are the 5.10
# dm-ioctl.c logic transcribed; the Python side asserts the transcription is still in the source.
DM_C_TEST=r'''
#include "probes.h"
#include <fcntl.h>
#include <assert.h>
#include <stddef.h>
static FILE *out;
static const struct dm_target_spec *kspec(const void *p){return p;}
// 5.10 check_version: major must match, user minor must not exceed the kernel's.
static int k_check_version(const struct dm_ioctl *h){
 return (DM_VERSION_MAJOR!=h->version[0]||DM_VERSION_MINOR<h->version[1])?-EINVAL:0;}
// 5.10 copy_params size rules.
static int k_copy_params(const struct dm_ioctl *h,size_t buffer_size){
 if(h->data_size<offsetof(struct dm_ioctl,data))return -EINVAL;
 if(h->data_size>buffer_size)return -EFAULT; // the kernel would copy past the user buffer
 return 0;}
// 5.10 validate_params for a named (non-create) or create command.
static int k_validate(const struct dm_ioctl *h,int create){
 if(create){if(!*h->name)return -EINVAL;}else if(*h->uuid&&*h->name)return -EINVAL;
 return memchr(h->name,0,DM_NAME_LEN)?0:-EINVAL;}
static int k_invalid_str(char *str,void *end){while((void*)str<end)if(!*str++)return 0;return -EINVAL;}
static int k_next_target(struct dm_target_spec *last,uint32_t next,void *end,struct dm_target_spec **spec,char **params){
 *spec=(struct dm_target_spec*)((unsigned char*)last+next);*params=(char*)(*spec+1);
 if(*spec<(last+1)){return -EINVAL;}
 return k_invalid_str(*params,end);}
// 5.10 populate_table, with dm_table_add_target replaced by recording the targets.
struct got{uint64_t start,len;char type[DM_MAX_TYPE_NAME];char params[96];};
static int k_populate(unsigned char *buf,struct got *g,unsigned *n){
 struct dm_ioctl *param=(struct dm_ioctl*)buf;size_t param_size=param->data_size;
 struct dm_target_spec *spec=(struct dm_target_spec*)param;uint32_t next=param->data_start;
 void *end=(void*)param+param_size;char *tp;
 if(!param->target_count)return -EINVAL;
 for(unsigned i=0;i<param->target_count;i++){
  int r=k_next_target(spec,next,end,&spec,&tp);if(r)return r;
  // the target's params and the spec itself must lie inside the buffer
  if((void*)(spec+1)>end)return -EINVAL;
  g[i].start=spec->sector_start;g[i].len=spec->length;
  snprintf(g[i].type,sizeof(g[i].type),"%s",spec->target_type);snprintf(g[i].params,sizeof(g[i].params),"%s",tp);
  next=spec->next;*n=i+1;}
 return 0;}
int main(int argc,char **argv){
 assert(argc==3);out=fopen(argv[1],"w");assert(out);(void)kspec;
 fprintf(out,"kernel-version %u.%u.%u\n",DM_VERSION_MAJOR,DM_VERSION_MINOR,DM_VERSION_PATCHLEVEL);
 fprintf(out,"sizeof dm_ioctl=%zu dm_target_spec=%zu\n",sizeof(struct dm_ioctl),sizeof(struct dm_target_spec));
 // Version check: ours accepted; the v10 value (the NDK header's 4.48.0) rejected by the 5.10 rule.
 struct dm_ioctl h;tp11_dm_header(&h,sizeof(h),"tp10-system");
 fprintf(out,"version-sent %u.%u.%u accepted=%d\n",h.version[0],h.version[1],h.version[2],k_check_version(&h)==0);
 struct dm_ioctl old=h;old.version[1]=48;fprintf(out,"version-4.48 accepted=%d\n",k_check_version(&old)==0);
 old.version[0]=3;old.version[1]=0;fprintf(out,"version-3.0 accepted=%d\n",k_check_version(&old)==0);
 // Create header.
 struct dm_ioctl c;tp11_dm_header(&c,sizeof(c),"tp10-system");c.flags=DM_READONLY_FLAG;
 fprintf(out,"create data_size=%u data_start=%u name=%s flags=%u copy=%d validate=%d uuid_empty=%d dev=%llu\n",c.data_size,c.data_start,c.name,c.flags,
  k_copy_params(&c,sizeof(c)),k_validate(&c,1),c.uuid[0]==0,(unsigned long long)c.dev);
 // Resume (DM_DEV_SUSPEND without DM_SUSPEND_FLAG) and remove headers.
 struct dm_ioctl r;tp11_dm_header(&r,sizeof(r),"tp10-system");
 fprintf(out,"resume suspend_flag=%d copy=%d validate=%d name=%s\n",!!(r.flags&DM_SUSPEND_FLAG),k_copy_params(&r,sizeof(r)),k_validate(&r,0),r.name);
 struct dm_ioctl d;tp11_dm_header(&d,sizeof(d),"tp10-system");
 fprintf(out,"remove deferred=%d copy=%d validate=%d name=%s\n",!!(d.flags&DM_DEFERRED_REMOVE),k_copy_params(&d,sizeof(d)),k_validate(&d,0),d.name);
 // Table loads: 1, 2, 3 and 16 (max) extents with awkward sizes (params of differing lengths).
 static const unsigned counts[]={1,2,3,16};
 for(unsigned t=0;t<4;++t){
  struct tp10_lp_partition part;memset(&part,0,sizeof(part));snprintf(part.name,sizeof(part.name),"system");
  part.num_extents=counts[t];
  uint64_t target=2048;
  for(unsigned x=0;x<part.num_extents;++x){part.extents[x].num_sectors=1000+(uint64_t)x*7919;part.extents[x].target_sector=target;target+=part.extents[x].num_sectors*(x%2?1:3)+(x*100003ull);part.sectors+=part.extents[x].num_sectors;}
  static unsigned char buf[8192];
  size_t size=tp11_dm_build_table(buf,sizeof(buf),"tp10-system",259,5,&part);
  struct dm_ioctl *l=(struct dm_ioctl*)buf;
  fprintf(out,"load %u size=%zu data_size=%u target_count=%u data_start=%u readonly=%d name=%s copy=%d validate=%d\n",counts[t],size,l->data_size,l->target_count,l->data_start,!!(l->flags&DM_READONLY_FLAG),l->name,k_copy_params(l,sizeof(buf)),k_validate(l,0));
  struct got g[16];unsigned n=0;memset(g,0,sizeof(g));
  int pr=k_populate(buf,g,&n);
  fprintf(out,"populate %u rc=%d targets=%u aligned=%d\n",counts[t],pr,n,(size%8)==0&&(l->data_start%8)==0);
  uint64_t logical=0;
  for(unsigned x=0;x<n;++x){
   char want[96];snprintf(want,sizeof(want),"259:5 %llu",(unsigned long long)part.extents[x].target_sector);
   fprintf(out,"target %u %u start=%llu len=%llu type=%s params=%s ok=%d\n",counts[t],x,(unsigned long long)g[x].start,(unsigned long long)g[x].len,g[x].type,g[x].params,
    g[x].start==logical&&g[x].len==part.extents[x].num_sectors&&!strcmp(g[x].type,"linear")&&!strcmp(g[x].params,want));
   logical+=part.extents[x].num_sectors;}
  // Every spec offset is 8-byte aligned and the last spec's params end inside data_size.
  size_t off=l->data_start;int aligned=1;
  for(unsigned x=0;x<l->target_count;++x){if(off%8)aligned=0;off+=((struct dm_target_spec*)(buf+off))->next;}
  fprintf(out,"walk %u aligned=%d end=%zu data_size=%u\n",counts[t],aligned,off,l->data_size);
  // A buffer one byte short of the params NUL must be rejected by invalid_str.
  if(t==0){l->data_size-=0;
   struct dm_target_spec *s0=(struct dm_target_spec*)(buf+l->data_start);
   size_t nul=l->data_start+sizeof(*s0)+strlen((char*)(s0+1));
   unsigned save=l->data_size;l->data_size=(uint32_t)nul;n=0;
   fprintf(out,"truncated-params rc=%d\n",k_populate(buf,g,&n));l->data_size=save;}
 }
 // Too many extents for the buffer returns 0, not an overflow.
 { struct tp10_lp_partition part;memset(&part,0,sizeof(part));part.num_extents=16;
   for(unsigned x=0;x<16;++x){part.extents[x].num_sectors=8;part.extents[x].target_sector=8;}
   static unsigned char tiny[700];
   fprintf(out,"load-small-buffer %zu\n",tp11_dm_build_table(tiny,sizeof(tiny),"x",1,2,&part));}
 // The stock super image's real extents, parsed by the LP parser and loaded as init would.
 { int fd=open(argv[2],O_RDONLY);assert(fd>=0);static unsigned char head[1u<<20];
   assert(read(fd,head,sizeof(head))==(ssize_t)sizeof(head));close(fd);
   static struct tp10_lp lp;const char *why="";assert(tp10_lp_parse(head,sizeof(head),&lp,&why)==3);
   for(unsigned i=0;i<lp.num_partitions;++i){struct tp10_lp_partition *p=&lp.partitions[i];
    static unsigned char buf[8192];size_t size=tp11_dm_build_table(buf,sizeof(buf),"tp10-x",259,5,p);
    struct got g[16];unsigned n=0;int rc=size?k_populate(buf,g,&n):-1;uint64_t logical=0;int ok=rc==0&&n==p->num_extents;
    for(unsigned x=0;ok&&x<n;++x){char want[96];snprintf(want,sizeof(want),"259:5 %llu",(unsigned long long)p->extents[x].target_sector);
     ok=g[x].start==logical&&g[x].len==p->extents[x].num_sectors&&!strcmp(g[x].params,want);logical+=g[x].len;}
    fprintf(out,"stock-load %s extents=%u size=%zu rc=%d total_sectors=%llu ok=%d\n",p->name,p->num_extents,size,rc,(unsigned long long)logical,ok&&logical==p->sectors);}}
 fclose(out);return 0;}
'''

def parse_super_first_mib():
 d=SUPER.open('rb').read(1<<20)
 base=12288; h=d[base:base+128]
 hsz=struct.unpack('<I',h[8:12])[0]; tsz=struct.unpack('<I',h[44:48])[0]
 lbs=struct.unpack('<I',d[4096+48:4096+52])[0]
 tables=d[base+hsz:base+hsz+tsz]
 po,pn,pe,eo,en,ee,go,gn,ge,bo,bn,be=struct.unpack('<IIIIIIIIIIII',h[80:128])
 bd=tables[bo:bo+be]; first_logical=struct.unpack('<Q',bd[0:8])[0]; dev_size=struct.unpack('<Q',bd[16:24])[0]
 groups={}
 for i in range(gn):
  rec=tables[go+i*ge:go+i*ge+ge]; groups[i]=rec[0:36].rstrip(b'\0').decode()
 main=[i for i,n in groups.items() if n=='main'][0]
 parts={}
 for i in range(pn):
  rec=tables[po+i*pe:po+i*pe+pe]; name=rec[0:36].rstrip(b'\0').decode()
  attrs,first_extent,num_extents,group=struct.unpack('<IIII',rec[36:52])
  exts=[]
  for x in range(num_extents):
   e=tables[eo+(first_extent+x)*ee:eo+(first_extent+x)*ee+ee]
   num_sectors,ttype,tdata,tsrc=struct.unpack('<QIQI',e[0:24]); exts.append((num_sectors,tdata)); assert ttype==0 and tsrc==0
  parts[name]={'group':group,'extents':exts,'sectors':sum(s for s,_ in exts)}
 return {'lbs':lbs,'first_logical':first_logical,'dev_size':dev_size,'main':main,'parts':parts}

def main():
 checks=0
 with tempfile.TemporaryDirectory(prefix='tp11-probes-') as tmp:
  tmp=Path(tmp)
  # A 3 MiB userdata file filled with deterministic bytes; the last 1 MiB is the region.
  import random
  rng=random.Random(10); data=bytearray(rng.randbytes(3<<20))
  udata=tmp/'userdata.img'; udata.write_bytes(bytes(data))
  whole_before=hashlib.sha256(data).hexdigest()
  region_orig=hashlib.sha256(data[2<<20:3<<20]).hexdigest()
  superfirst=tmp/'super-first.img'; superfirst.write_bytes(SUPER.open('rb').read(1<<20))
  src=tmp/'t.c'; src.write_text(C_TEST); exe=tmp/'t'; outp=tmp/'out.txt'
  # -Wno-unused-function: this harness exercises only the v11 additions; the v9 helpers
  # it does not call are covered by check-pocket-diagnostic-v9-probes.py.
  subprocess.run(['cc','-std=gnu11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-fno-sanitize-recover=all',
                  '-I',str(HEADER.parent),str(src),'-o',str(exe)],check=True)
  subprocess.run([str(exe),str(outp),str(udata),str(superfirst)],check=True)
  lines=outp.read_text().splitlines()
  budget=(2<<20)+4096
  # Clean run: all steps pass, restore matches, the region's original hash is logged, budget respected.
  clean=next(l for l in lines if l.startswith('write-result clean '))
  assert ' step1=1 step2=1 step3=1 restore_attempted=1 restore=1 ' in clean,clean;checks+=1
  assert f' orig={region_orig} ' in clean,clean;checks+=1
  bytes_written=int(re.search(r'bytes=(\d+)',clean).group(1)); assert bytes_written==(2<<20)+4096 and bytes_written<=budget;checks+=1
  assert f'budget={budget}' in clean;checks+=1
  assert 'userdata-write complete bytes_written=%d budget=%d within_budget=1'%(bytes_written,budget) in lines;checks+=1
  # The file is byte-identical after the clean run: the region is restored and nothing outside it changed.
  assert hashlib.sha256(udata.read_bytes()).hexdigest()==whole_before,'clean write test did not restore the file exactly';checks+=1
  # Restore after a failed write, for a step 2 and a step 3 failure.
  for name,s2,s3 in [('fail2',0,None),('fail3',1,0)]:
   row=next(l for l in lines if l.startswith('write-result '+name+' '))
   assert ' step1=1 ' in row and ' restore_attempted=1 restore=1 ' in row,row
   assert (' step2=%d '%s2) in row,row
   if s3 is not None: assert (' step3=%d '%s3) in row,row
   assert int(re.search(r'bytes=(\d+)',row).group(1))<=budget;checks+=1
  assert 'userdata restore FAILED' not in lines,'restore reported FAILED on a file that accepts writes';checks+=1
  # LP parser against the stock super image.
  expect=parse_super_first_mib()
  lp=next(l for l in lines if l.startswith('lp count='))
  assert f'lp count=3 why= lbs={expect["lbs"]} first_logical_sector={expect["first_logical"]} device_size={expect["dev_size"]}' in lp,lp;checks+=1
  assert sorted(expect['parts'])==['product','system','vendor'];checks+=1
  for name,info in expect['parts'].items():
   assert info['group']==expect['main']
   assert f'lp-part {name} group={info["group"]} extents={len(info["extents"])} sectors={info["sectors"]}' in lines,name;checks+=1
   for x,(num,target) in enumerate(info['extents']):
    assert f'lp-extent {name} {x} num={num} target={target}' in lines,(name,x);checks+=1
  # Negative cases: each flipped checksum field and a short buffer are rejected.
  assert 'lp-bad 0 -1' in lines and 'lp-bad-why 0 geometry_checksum' in lines;checks+=1
  assert 'lp-bad 1 -1' in lines and 'lp-bad-why 1 header_checksum' in lines;checks+=1
  assert 'lp-bad 2 -1' in lines and 'lp-bad-why 2 tables_checksum' in lines;checks+=1
  assert 'lp-short -1' in lines;checks+=1
  # Touchpad reset test: stock's sequence, about 420 ms plus a 5 ms gap, and the result lines.
  pad=next(l for l in lines if l.startswith('pad gpio='))
  assert pad=='pad gpio=9 steps=3 1:200000 0:20000 1:200000 gap=5000 sleep_us=425000',pad;checks+=1
  assert 'pad-need nack_nack=1 ok_nack=0 nack_ok=0 timeout_nack=0' in lines;checks+=1
  assert 'i2c bus=6 adapter=3 addr=0x20 chip=synaptics-pad reg=e9 id=010203040506 result=ok supply=none ms=12 reset=pulsed' in lines;checks+=1
  assert 'i2c bus=6 adapter=3 addr=0x2c chip=synaptics-pad reg=e9 id=- result=error status=-1 errno=6 supply=none ms=2 reset=pulsed' in lines;checks+=1
  assert 'i2c bus=4 adapter=4 addr=0x58 chip=aw9523 reg=10 id=01 expect=23 match=no result=ok' not in lines;checks+=1
  assert 'i2c bus=4 adapter=4 addr=0x58 chip=aw9523 reg=10 id=01 result=ok expect=23 match=no supply=none ms=3' in lines;checks+=1
  # Read-only rule in the init source: the only writable opens are the watchdog (O_WRONLY)
  # and the userdata node (O_RDWR); every other open is read-only.
  init=INIT.read_text()
  opens=re.findall(r'open\([^;]*?,\s*(O_[A-Z_0-9 |]+)\)',init)
  rdwr=[o for o in opens if 'O_RDWR' in o]; wronly=[o for o in opens if 'O_WRONLY' in o]
  assert rdwr==['O_RDWR | O_DIRECT | O_CLOEXEC | O_NOFOLLOW'],rdwr;checks+=1
  assert wronly==['O_WRONLY | O_CLOEXEC | O_NOFOLLOW'],wronly;checks+=1
  assert 'open(node, O_RDWR | O_DIRECT | O_CLOEXEC | O_NOFOLLOW)' in init;checks+=1
  assert 'the one writable open in init' in init.lower() or 'the only writable open in init' in init.lower();checks+=1
  # The dm control, super node and dm nodes are opened read-only.
  for ro in ['open("/dev/mapper/control", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)',
             'open("/dev/device-mapper", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)']:
   assert ro in init,ro;checks+=1
  assert init.count('O_RDWR')==1,'more than one O_RDWR open in init';checks+=1
  # The super mount is ext4, read-only, with the stock flags and no journal recovery.
  assert 'mount(node, mountpoint, "ext4", MS_RDONLY | MS_NODEV | MS_NOSUID | MS_NOEXEC, "noload")' in init;checks+=1
  # dm devices are created read-only and resumed; no write-enabling dm flag.
  assert init.count('DM_READONLY_FLAG')==1 and 'load->flags = DM_READONLY_FLAG' in HEADER.read_text() and 'DM_DEV_CREATE' in init and 'DM_TABLE_LOAD' in init;checks+=1
  assert 'DM_DEV_SUSPEND' in init and 'DM_DEV_REMOVE' in init and 'DM_SUSPEND_FLAG' not in init;checks+=1
  # The super hash runs last, after the two tests, so it proves the mount wrote nothing.
  order=[init.index(s) for s in ['tp8_hash_range(fd, part->name','userdata_write_test(disk','super_mount_test(disk','tp8_hash_range(fd, "super"']]
  assert order==sorted(order),'super must be hashed last';checks+=1
  # ---- dm-ioctl builders against the 5.10 kernel rules ----
  kdm=KERNEL_DM_HEADER.read_text()
  assert re.search(r'#define DM_VERSION_MAJOR\s+4\b',kdm) and re.search(r'#define DM_VERSION_MINOR\s+44\b',kdm);checks+=1
  kc=KERNEL_DM_C.read_text()
  # The transcribed kernel logic is still what 5.10 dm-ioctl.c says.
  for frag in ['(DM_VERSION_MAJOR != version[0]) ||\n\t    (DM_VERSION_MINOR < version[1])',
               '*spec = (struct dm_target_spec *) ((unsigned char *) last + next);',
               'if (*spec < (last + 1))','return invalid_str(*target_params, end);',
               'uint32_t next = param->data_start;','void *end = (void *) param + param_size;',
               'next = spec->next;','if (!param->target_count)',
               'param_kernel->data_size > DM_MAX_TARGETS * DM_MAX_TARGET_PARAMS']:
   assert frag in kc,frag;checks+=1
  inc=tmp/'inc'/'linux';inc.mkdir(parents=True);(inc/'dm-ioctl.h').write_text(kdm)
  dsrc=tmp/'d.c';dsrc.write_text(DM_C_TEST);dexe=tmp/'d';dout=tmp/'dm-out.txt'
  subprocess.run(['cc','-std=gnu11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-fno-sanitize-recover=all',
                  '-I',str(tmp/'inc'),'-I',str(HEADER.parent),str(dsrc),'-o',str(dexe)],check=True)
  subprocess.run([str(dexe),str(dout),str(superfirst)],check=True)
  dl=dout.read_text().splitlines()
  assert 'kernel-version 4.44.0' in dl;checks+=1
  assert 'sizeof dm_ioctl=312 dm_target_spec=40' in dl;checks+=1
  assert 'version-sent 4.0.0 accepted=1' in dl;checks+=1
  assert 'version-4.48 accepted=0' in dl and 'version-3.0 accepted=0' in dl;checks+=1
  assert 'create data_size=312 data_start=312 name=tp10-system flags=1 copy=0 validate=0 uuid_empty=1 dev=0' in dl;checks+=1
  assert 'resume suspend_flag=0 copy=0 validate=0 name=tp10-system' in dl;checks+=1
  assert 'remove deferred=0 copy=0 validate=0 name=tp10-system' in dl;checks+=1
  for n in (1,2,3,16):
   row=next(l for l in dl if l.startswith(f'load {n} '))
   m=re.search(r'size=(\d+) data_size=(\d+) target_count=(\d+) data_start=(\d+) readonly=1 name=tp10-system copy=0 validate=0',row);assert m,row
   assert int(m.group(1))==int(m.group(2)) and int(m.group(3))==n and int(m.group(4))==312 and int(m.group(2))<=8192;checks+=1
   assert f'populate {n} rc=0 targets={n} aligned=1' in dl;checks+=1
   tl=[l for l in dl if l.startswith(f'target {n} ')];assert len(tl)==n and all(l.endswith('ok=1') for l in tl),tl;checks+=1
   w=next(l for l in dl if l.startswith(f'walk {n} '));assert 'aligned=1' in w;checks+=1
  assert 'truncated-params rc=-22' in dl;checks+=1
  assert 'load-small-buffer 0' in dl;checks+=1
  for name,info in expect['parts'].items():
   row=next(l for l in dl if l.startswith(f'stock-load {name} '))
   assert f'extents={len(info["extents"])} ' in row and ' rc=0 ' in row and f'total_sectors={info["sectors"]} ok=1' in row,row;checks+=1
  # init.c uses the shared builders and logs the DM_VERSION failure with errno.
  assert 'tp11_dm_build_table(' in init and 'tp11_dm_header(' in init and 'dm_header(&' not in init.replace('tp11_dm_header(&','');checks+=1
  assert 'DM_VERSION_MINOR' not in init.replace('//','') and 'dm version ioctl errno=%d' in init;checks+=1
  assert '#define TP11_DM_VERSION_MINOR 0u' in HEADER.read_text() and '#define TP11_DM_VERSION_MAJOR 4u' in HEADER.read_text();checks+=1
  # init.c wiring: GPIO 9 is only requested by the pad test, GPIO writes stay on lines 178 and 9, rails are read-only.
  assert init.count('tp11_pad_needs_reset(')==1 and init.count('pad_reset_test(pad[0]')==1;checks+=1
  assert init.count('gpio_request_output_high(')==3 and 'gpio_request_output_high(TP11_PAD_RESET_GPIO' in init and 'gpio_request_output_high(TP9_AW9523_RESET_GPIO' in init;checks+=1
  assert all(f'"{r}"' in init for r in ('vio18','vio28','vibr')) and 'regulator_state(rails[i]' in init;checks+=1
  assert 'tp11_i2c_line(' in init and init.count('result=ok')==0;checks+=1
  # The pattern carries only a marker, a counter and the LBA, never user data.
  header=HEADER.read_text()
  assert '#define TP10_WR_MARKER "TP10-USERDATA-WR"' in header and '#define TP10_WR_FUA_MARKER "TP10-USERDATA-FUA"' in header;checks+=1
 record={'checks':checks,'sanitizers':['address','undefined'],
         'header_sha256':hashlib.sha256(HEADER.read_bytes()).hexdigest(),
         'init_sha256':hashlib.sha256(INIT.read_bytes()).hexdigest(),
         'tool_sha256':hashlib.sha256(TOOL.read_bytes()).hexdigest(),
         'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'super_first_mib_sha256':hashlib.sha256(SUPER.open('rb').read(1<<20)).hexdigest(),
         'device_accessed':False,
         'limits':['Host x86-64 build of the helpers; the ARM64 init is compiled separately and not run here',
                   'The write test runs against a sparse file through the callback ops, not a UFS device; FUA/FLUSH, O_DIRECT and real restore timing are only seen on the phone',
                   'The dm ioctl buffers are checked against a transcription of the 5.10 dm-ioctl.c rules, not a running kernel',
                   'The LP parser is checked against the stock super image; the dm-linear build, mount and super re-hash are device-only']}
 (ROOT/'evidence/kernel-upgrade/diagnostic-probes-check-v11.json').write_text(json.dumps(record,indent=2)+'\n')
 print(f'{checks} v11 probe helper checks passed under ASan/UBSan; no device access')
if __name__=='__main__':main()

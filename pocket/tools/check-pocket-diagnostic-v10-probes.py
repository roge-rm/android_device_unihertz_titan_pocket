#!/usr/bin/env python3
"""Host-test the v10 probe helpers added over v9: the userdata restore-on-exit write test
(driven through callbacks against a sparse file, including restore after a simulated failed
write and a check that writes stay inside the region) and the LP (super) metadata parser
(against the first 1 MiB of the stock super image). Also checks the read-only rule in the
v10 init source: the only writable open is the userdata node. ASan/UBSan, synthetic or
stock-image data only; never accesses a phone."""
import hashlib,json,os,re,struct,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
HEADER=ROOT/'kernel-upgrade/diagnostic-probe-v10/probes.h'
INIT=ROOT/'kernel-upgrade/diagnostic-probe-v10/init.c'
SUPER=ROOT/'firmware/installed-20230105/super.raw.img'
TOOL=ROOT/'tools/pocket-partition-hashes.py'

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
 with tempfile.TemporaryDirectory(prefix='tp10-probes-') as tmp:
  tmp=Path(tmp)
  # A 3 MiB userdata file filled with deterministic bytes; the last 1 MiB is the region.
  import random
  rng=random.Random(10); data=bytearray(rng.randbytes(3<<20))
  udata=tmp/'userdata.img'; udata.write_bytes(bytes(data))
  whole_before=hashlib.sha256(data).hexdigest()
  region_orig=hashlib.sha256(data[2<<20:3<<20]).hexdigest()
  superfirst=tmp/'super-first.img'; superfirst.write_bytes(SUPER.open('rb').read(1<<20))
  src=tmp/'t.c'; src.write_text(C_TEST); exe=tmp/'t'; outp=tmp/'out.txt'
  # -Wno-unused-function: this harness exercises only the v10 additions; the v9 helpers
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
  assert init.count('DM_READONLY_FLAG')==2 and 'DM_DEV_CREATE' in init and 'DM_TABLE_LOAD' in init;checks+=1
  assert 'DM_DEV_SUSPEND' in init and 'DM_DEV_REMOVE' in init and 'DM_SUSPEND_FLAG' not in init;checks+=1
  # The super hash runs last, after the two tests, so it proves the mount wrote nothing.
  order=[init.index(s) for s in ['tp8_hash_range(fd, part->name','userdata_write_test(disk','super_mount_test(disk','tp8_hash_range(fd, "super"']]
  assert order==sorted(order),'super must be hashed last';checks+=1
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
                   'The LP parser is checked against the stock super image; the dm-linear build, mount and super re-hash are device-only']}
 (ROOT/'evidence/kernel-upgrade/diagnostic-probes-check-v10.json').write_text(json.dumps(record,indent=2)+'\n')
 print(f'{checks} v10 probe helper checks passed under ASan/UBSan; no device access')
if __name__=='__main__':main()

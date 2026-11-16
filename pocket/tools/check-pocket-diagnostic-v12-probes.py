#!/usr/bin/env python3
"""Host-test the v12 probe helpers added over v11: the teed command-line builder (every writable
path kept under one tmpfs root, no --rpmbdev and no short -p/-r, anything else refused) and the
raw-ioctl TEEC client (feature query 0x800474b7 then session open 0xc03074a1 on /dev/tkcoredrv
for the keymaster TA, as stock libteec does, driven through callbacks against a fake driver that
runs the 5.10 driver's own checks on the SHM, open-session and feature ioctls). Includes the
failing cases: an rpmb option, a path outside tmpfs, a wrong ioctl size, SHM fd_shm -1 and a
NULL operation. The
five ioctl constants and nine LP64 layouts are static-asserted against the stock tkcore headers
and compiled for ARM32 and ARM64 as well. ASan/UBSan, synthetic data only; never accesses a phone."""
import pocket_paths
import hashlib,json,re,struct,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
HEADER=ROOT/'kernel-upgrade/diagnostic-probe-v12/probes.h'
INIT=ROOT/'kernel-upgrade/diagnostic-probe-v12/init.c'
TKCORE=ROOT/'tools/kernel-source/upgrade-5.10/drivers/misc/mediatek/tkcore'
TEE_IOC=TKCORE/'include/linux/tee_ioc.h'
TEE_API=TKCORE/'include/linux/tee_client_api.h'
KEYMASTER=ROOT/'evidence/kernel-upgrade/trustkernel-keymaster-5.10.md'
LIBTEEC_EVIDENCE=ROOT/'evidence/kernel-upgrade/v12-teed-contract/libteec-context-session.txt'
MANIFEST=ROOT/'backups/stock-20261029T001105.670723Z/manifest.json'
CLANG=str(pocket_paths.ndk_bin() / 'clang')

# The teed option values and the TA uuid come from the saved REA, not from guessing; the Python
# side pins them so a change to the header or the evidence is caught.
TMPFS_ROOT='/mnt/tk-tmp'
EXPECT_ARGV=['teed',
 '--systapath','/vendor/app/t6',
 '--proprefix','vendor.trustkernel',
 '--prot',TMPFS_ROOT+'/persist/t6',
 '--prot',TMPFS_ROOT+'/protect_f/tee',
 '--datapath',TMPFS_ROOT+'/fs',
 '--sptapath',TMPFS_ROOT+'/app',
 '--logpath',TMPFS_ROOT+'/tkcore.log']
TA_UUID='9ef77781-7bd5-4e39'

C_TEST=r'''
#include "probes.h"
#include <assert.h>
static FILE *out;
static void report(const char *m){fprintf(out,"%s\n",m);}

// A fake tkcore driver so the TEEC client runs with no device. The three ioctls the client could
// reach run the checks of the 5.10 driver (tee_core.c tee_do_shm_alloc, tee_do_create_session and
// TEE_QUERY_DRV_FEATURE_IOC, tee_session.c _init_tee_cmd), transcribed below; the Python side
// asserts the source still says so. The ioctl works on a copy of the argument and writes back
// only the fields the driver puts back. The TEE answer itself is scripted.
#define K_SHM_FLAGS (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT | TEEC_MEM_NONSECURE)
struct fakedrv{
 int next_fd,open_errno,session_errno,feature_errno;
 unsigned long ioctls[8];unsigned n;
 uint32_t features,teec_result,origin;int session_fd,shm_fd;
 struct TEEC_UUID seen_uuid;int uuid_seen,op_seen,fd_sess_seen;uint32_t cmd_seen,data_size_seen,param_types_seen,origin_in;
 unsigned rejected;};
static int k_shm_alloc(struct fakedrv *d,struct tee_shm_io *u){
 struct tee_shm_io k;memcpy(&k,u,sizeof(k));
 if((k.buffer!=NULL)||(k.fd_shm!=0)||((k.flags&K_SHM_FLAGS)==0)||(k.registered!=0)){++d->rejected;return -EINVAL;}
 u->fd_shm=d->shm_fd;u->flags=k.flags;return 0;}
static int k_create_session(struct fakedrv *d,struct tee_cmd_io *u){
 struct tee_cmd_io k;memcpy(&k,u,sizeof(k));
 if(k.fd_sess>0){++d->rejected;return -EINVAL;}
 if((k.op==NULL)||(k.uuid==NULL)||((k.data!=NULL)&&(k.data_size==0))||((k.data==NULL)&&(k.data_size!=0))){++d->rejected;return -EINVAL;}
 d->fd_sess_seen=k.fd_sess;d->cmd_seen=k.cmd;d->data_size_seen=k.data_size;d->origin_in=k.origin;
 // _init_tee_cmd: err and origin preset, then a whole TEEC_Operation and the uuid copied in.
 k.origin=TEEC_ORIGIN_TEE;k.err=TEEC_ERROR_BAD_PARAMETERS;
 struct TEEC_Operation op;memcpy(&op,k.op,sizeof(op));d->op_seen=1;d->param_types_seen=op.paramTypes;
 int ret=0;
 for(int idx=0;idx<TEEC_CONFIG_PAYLOAD_REF_COUNT;++idx)
  if(TEEC_PARAM_TYPE_GET(op.paramTypes,idx)!=TEEC_NONE){++d->rejected;ret=-EINVAL;}  // not modelled
 if(!ret){memcpy(&d->seen_uuid,k.uuid,sizeof(d->seen_uuid));d->uuid_seen=1;}
 if(!ret&&d->session_errno)ret=d->session_errno;
 if(!ret){k.err=d->teec_result;k.origin=d->origin;}
 // tee_session_create_fd: fd -1 on a TEE error (ioctl still 0), a session fd on success.
 if(!ret)k.fd_sess=k.err?-1:d->session_fd;
 u->err=k.err;u->origin=k.origin;
 if(ret)return ret;
 u->fd_sess=k.fd_sess;return 0;}
static int k_feature(struct fakedrv *d,uint32_t *u){if(d->feature_errno)return d->feature_errno;if(!u)return -EINVAL;*u=d->features;return 0;}
static int fk_open(void *c,const char *path){struct fakedrv *d=c;fprintf(out,"open %s\n",path);
 return d->open_errno?d->open_errno:d->next_fd;}
static int fk_ioctl(void *c,int fd,unsigned long req,void *arg){struct fakedrv *d=c;(void)fd;
 if(d->n<8)d->ioctls[d->n++]=req;
 if(req==TP12_TEEC_CONTEXT_SHM_IOC)return k_shm_alloc(d,arg);
 if(req==TP12_TEEC_OPEN_SESSION_IOC)return k_create_session(d,arg);
 if(req==TP12_TEEC_VERSION_IOC)return k_feature(d,arg);
 return -EINVAL;}
static void fk_close(void *c,int fd){(void)c;(void)fd;}
static void fake_init(struct fakedrv *d){memset(d,0,sizeof(*d));d->next_fd=7;d->shm_fd=9;d->session_fd=11;d->features=0;}

static void dump_build(const char *tag,const char *root){
 struct tp12_teed b;int argc=tp12_teed_build(&b,root);
 fprintf(out,"build %s argc=%d error=%d\n",tag,argc,b.error);
 if(argc>0){fprintf(out,"cmdline %s",tag);for(unsigned i=0;i<b.count;++i)fprintf(out," %s",b.args[i]);fprintf(out,"\n");}}

int main(int argc,char **argv){
 assert(argc==3);out=fopen(argv[1],"w");assert(out);
 // ---- teed builder ----
 dump_build("clean","/mnt/tk-tmp");
 dump_build("otherroot","/data/local/tk");
 // A bad root is refused and emits nothing.
 dump_build("dotdot","/mnt/../etc");
 dump_build("relative","mnt/tk");
 dump_build("trailing","/mnt/tk/");
 // Classification: forbidden, kept, writable, unknown.
 fprintf(out,"class rpmbdev=%d sdrpmbdev=%d prebuilt=%d nofrp=%d p=%d r=%d prot=%d datapath=%d systapath=%d proprefix=%d junk=%d\n",
  tp12_teed_classify("--rpmbdev"),tp12_teed_classify("--sdrpmbdev"),tp12_teed_classify("--prebuilt"),tp12_teed_classify("--nofrp"),
  tp12_teed_classify("-p"),tp12_teed_classify("-r"),
  tp12_teed_classify("--prot"),tp12_teed_classify("--datapath"),tp12_teed_classify("--systapath"),
  tp12_teed_classify("--proprefix"),tp12_teed_classify("--nope"));
 // Refusal: adding a forbidden or unknown option fails and leaves the builder untouched.
 {struct tp12_teed b;tp12_teed_init(&b,"/mnt/tk-tmp");
  int rc=tp12_teed_add(&b,"--rpmbdev",0);fprintf(out,"add rpmbdev rc=%d error=%d count=%u\n",rc,b.error,b.count);}
 {struct tp12_teed b;tp12_teed_init(&b,"/mnt/tk-tmp");
  int rc=tp12_teed_add(&b,"-p",0);fprintf(out,"add p rc=%d error=%d\n",rc,b.error);}
 {struct tp12_teed b;tp12_teed_init(&b,"/mnt/tk-tmp");
  int rc=tp12_teed_add(&b,"--bogus",0);fprintf(out,"add bogus rc=%d error=%d\n",rc,b.error);}
 {const char *more[]={"--sdrpmbdev","--prebuilt","--nofrp"};
  for(unsigned i=0;i<3;++i){struct tp12_teed b;tp12_teed_init(&b,"/mnt/tk-tmp");
   int rc=tp12_teed_add(&b,more[i],0);fprintf(out,"add %s rc=%d error=%d count=%u\n",more[i]+2,rc,b.error,b.count);}}
 // Path-under-tmpfs guard.
 fprintf(out,"under in=%d out=%d dotdot=%d exact=%d rel=%d\n",
  tp12_path_under_tmpfs("/mnt/tk-tmp","/mnt/tk-tmp/fs"),
  tp12_path_under_tmpfs("/mnt/tk-tmp","/data/vendor/t6/fs"),
  tp12_path_under_tmpfs("/mnt/tk-tmp","/mnt/tk-tmp/../x"),
  tp12_path_under_tmpfs("/mnt/tk-tmp","/mnt/tk-tmp"),
  tp12_path_under_tmpfs("mnt","mnt/x"));
 // ---- TEEC client ----
 // Success: node opens, the feature query, the session opens, TEE returns success.
 {struct fakedrv d;fake_init(&d);d.teec_result=TEEC_SUCCESS;d.origin=3;
  static const struct tp12_teec_ops ops={fk_open,fk_ioctl,fk_close};struct tp12_teec_result r;
  int rc=tp12_teec_open_session(&ops,&d,&tp12_km_ta_uuid,&r,report);
  fprintf(out,"teec ok rc=%d opened=%d feature=%d sent=%d err=%d result=0x%08x origin=%u sess=%d rejected=%u\n",
   rc,r.opened,r.feature_queried,r.session_sent,r.error,(unsigned)r.teec_result,r.origin,r.session_fd,d.rejected);
  fprintf(out,"teec seq n=%u first=0x%lx second=0x%lx uuid_seen=%d op_seen=%d param_types=%u fd_sess=%d origin_in=%u cmd=%u data_size=%u\n",
   d.n,d.ioctls[0],d.ioctls[1],d.uuid_seen,d.op_seen,d.param_types_seen,d.fd_sess_seen,d.origin_in,d.cmd_seen,d.data_size_seen);
  fprintf(out,"teec uuid %08x-%04x-%04x node=%02x%02x\n",d.seen_uuid.timeLow,d.seen_uuid.timeMid,d.seen_uuid.timeHiAndVersion,d.seen_uuid.clockSeqAndNode[0],d.seen_uuid.clockSeqAndNode[7]);}
 // The feature word is carried back; a failed feature query is logged and the session still
 // opens, as stock ignores it.
 {struct fakedrv d;fake_init(&d);d.teec_result=TEEC_SUCCESS;d.features=0x5;
  static const struct tp12_teec_ops ops={fk_open,fk_ioctl,fk_close};struct tp12_teec_result r;
  int rc=tp12_teec_open_session(&ops,&d,&tp12_km_ta_uuid,&r,report);
  fprintf(out,"teec features rc=%d feature=%d features=0x%x\n",rc,r.feature_queried,(unsigned)r.features);}
 {struct fakedrv d;fake_init(&d);d.teec_result=TEEC_SUCCESS;d.feature_errno=-ENOTTY;
  static const struct tp12_teec_ops ops={fk_open,fk_ioctl,fk_close};struct tp12_teec_result r;
  int rc=tp12_teec_open_session(&ops,&d,&tp12_km_ta_uuid,&r,report);
  fprintf(out,"teec featurefail rc=%d feature=%d sent=%d sess=%d\n",rc,r.feature_queried,r.session_sent,r.session_fd);}
 // Failure: a TEE-side non-zero result is reported, rc<0, no session fd.
 {struct fakedrv d;fake_init(&d);d.teec_result=0xffff0006;d.origin=4;
  static const struct tp12_teec_ops ops={fk_open,fk_ioctl,fk_close};struct tp12_teec_result r;
  int rc=tp12_teec_open_session(&ops,&d,&tp12_km_ta_uuid,&r,report);
  fprintf(out,"teec teefail rc=%d result=0x%08x origin=%u sent=%d sess=%d err=%d\n",rc,(unsigned)r.teec_result,r.origin,r.session_sent,r.session_fd,r.error);}
 // Failure: the open-session ioctl itself errors (ENODEV); the driver still puts err and origin.
 {struct fakedrv d;fake_init(&d);d.session_errno=-ENODEV;
  static const struct tp12_teec_ops ops={fk_open,fk_ioctl,fk_close};struct tp12_teec_result r;
  int rc=tp12_teec_open_session(&ops,&d,&tp12_km_ta_uuid,&r,report);
  fprintf(out,"teec ioctlfail rc=%d err=%d sent=%d result=0x%08x origin=%u sess=%d\n",rc,r.error,r.session_sent,(unsigned)r.teec_result,r.origin,r.session_fd);}
 // Failure: the node cannot be opened.
 {struct fakedrv d;fake_init(&d);d.open_errno=-EACCES;
  static const struct tp12_teec_ops ops={fk_open,fk_ioctl,fk_close};struct tp12_teec_result r;
  int rc=tp12_teec_open_session(&ops,&d,&tp12_km_ta_uuid,&r,report);
  fprintf(out,"teec openfail rc=%d err=%d opened=%d\n",rc,r.error,r.opened);}
 // The fake driver refuses what the real one refuses. SHM as stock TEEC_AllocateSharedMemory
 // builds it (buffer NULL, flags 3, fd_shm 0, registered 0) is taken; each bad field is refused.
 {struct {const char *tag;struct tee_shm_io s;} c[]={
   {"stock",{{NULL},0x8000,TEEC_MEM_INPUT|TEEC_MEM_OUTPUT,0,0}},
   {"fd-minus1",{{NULL},0x8000,TEEC_MEM_INPUT|TEEC_MEM_OUTPUT,-1,0}},
   {"fd-5",{{NULL},0x8000,TEEC_MEM_INPUT|TEEC_MEM_OUTPUT,5,0}},
   {"buffer",{{(void*)&c},0x8000,TEEC_MEM_INPUT|TEEC_MEM_OUTPUT,0,0}},
   {"flags0",{{NULL},0x8000,0,0,0}},
   {"dmabuf-only",{{NULL},0x8000,TEEC_MEM_DMABUF,0,0}},
   {"registered",{{NULL},0x8000,TEEC_MEM_INPUT,0,1}}};
  for(unsigned i=0;i<sizeof(c)/sizeof(c[0]);++i){struct fakedrv d;fake_init(&d);
   int rc=fk_ioctl(&d,7,TP12_TEEC_CONTEXT_SHM_IOC,&c[i].s);fprintf(out,"kshm %s rc=%d fd=%d\n",c[i].tag,rc,c[i].s.fd_shm);}}
 // Open-session envelopes: the client's is taken; a NULL op, NULL uuid, a positive fd_sess,
 // data without a size, a size without data and a non-NONE parameter are each refused.
 {struct TEEC_Operation op0;
  struct {const char *tag;int null_op,null_uuid,fd_sess,data,data_size;uint32_t types;} c[]={
   {"client",0,0,-1,0,0,0},{"op-null",1,0,-1,0,0,0},{"uuid-null",0,1,-1,0,0,0},{"fd-sess-1",0,0,1,0,0,0},
   {"fd-sess-0",0,0,0,0,0,0},{"data-nosize",0,0,-1,1,0,0},{"size-nodata",0,0,-1,0,4,0},{"value-param",0,0,-1,0,0,TEEC_VALUE_INPUT}};
  for(unsigned i=0;i<sizeof(c)/sizeof(c[0]);++i){struct fakedrv d;fake_init(&d);d.teec_result=TEEC_SUCCESS;
   struct tee_cmd_io io;tp12_teec_fill_open(&io,&tp12_km_ta_uuid,&op0);
   if(c[i].null_op)io.op=NULL;
   if(c[i].null_uuid)io.uuid=NULL;
   io.fd_sess=c[i].fd_sess;if(c[i].data)io.data=&op0;io.data_size=c[i].data_size;op0.paramTypes=c[i].types;
   int rc=fk_ioctl(&d,7,TP12_TEEC_OPEN_SESSION_IOC,&io);fprintf(out,"kopen %s rc=%d sess=%d\n",c[i].tag,rc,io.fd_sess);}}
 // The client's envelope field by field, against the stock libteec layout.
 {struct TEEC_Operation op;memset(&op,0x5a,sizeof(op));struct tee_cmd_io io;memset(&io,0x5a,sizeof(io));
  tp12_teec_fill_open(&io,&tp12_km_ta_uuid,&op);
  unsigned char zero[sizeof(op)];memset(zero,0,sizeof(zero));
  fprintf(out,"fill err=%u origin=%u cmd=%u fd_sess=%d uuid=%d data=%d data_size=%u reserved=%d op=%d op_zero=%d\n",
   io.err,io.origin,io.cmd,io.fd_sess,io.uuid==&tp12_km_ta_uuid,io.data==NULL,io.data_size,io.reserved,io.op==&op,!memcmp(&op,zero,sizeof(op)));}
 // The feature ioctl refuses a NULL argument.
 {struct fakedrv d;fake_init(&d);fprintf(out,"kfeature null rc=%d\n",fk_ioctl(&d,7,TP12_TEEC_VERSION_IOC,NULL));}
 // The ioctl constants and sizes.
 fprintf(out,"const version=0x%lx ctx=0x%lx ctxperm=0x%lx session=0x%lx invoke=0x%lx\n",
  TP12_TEEC_VERSION_IOC,TP12_TEEC_CONTEXT_SHM_IOC,TP12_TEEC_CONTEXT_SHM_PERM_IOC,TP12_TEEC_OPEN_SESSION_IOC,TP12_TEEC_INVOKE_IOC);
 fprintf(out,"size cmd_io=%zu shm_io=%zu operation=%zu\n",sizeof(struct tee_cmd_io),sizeof(struct tee_shm_io),sizeof(struct TEEC_Operation));
 // Wrong ioctl size: the session ioctl built with a 4-byte payload is a different number, so the
 // 48-byte struct tee_cmd_io size is load-bearing.
 fprintf(out,"wrong-size ioc=0x%lx matches=%d\n",(unsigned long)_IOWR('t',161,uint32_t),(unsigned long)_IOWR('t',161,uint32_t)==TP12_TEEC_OPEN_SESSION_IOC);
 // ---- property area ----
 // The teed area: built, written for the Python and bionic readers, and looked up in C.
 {static unsigned char area[TP12_PROP_AREA_SIZE];struct tp12_props a;
  int rc=tp12_prop_build_teed(&a,area,sizeof(area));
  fprintf(out,"props build rc=%d error=%d used=%u size=%u\n",rc,a.error,a.used,a.size);
  FILE *f=fopen(argv[2],"wb");assert(f);assert(fwrite(area,1,sizeof(area),f)==sizeof(area));fclose(f);
  struct tp12_props r;fprintf(out,"props open rc=%d\n",tp12_prop_open(&r,area,sizeof(area)));
  for(size_t i=0;i<TP12_TEED_PROPS;++i){const char *v=tp12_prop_find(&r,tp12_teed_props[i].name);
   fprintf(out,"props find %s=%s\n",tp12_teed_props[i].name,v?v:"(null)");}
  const char *misses[]={"ro.product.device","ro.product","vendor.trustkernel.ready","ro..brand","ro.product.brand.","",".ro"};
  for(unsigned i=0;i<7;++i){const char *v=tp12_prop_find(&r,misses[i]);fprintf(out,"props miss '%s'=%s\n",misses[i],v?v:"(null)");}
  // A wrong magic or version is refused, as map_fd_ro does.
  static unsigned char bad[TP12_PROP_AREA_SIZE];memcpy(bad,area,sizeof(bad));bad[8]^=1;
  fprintf(out,"props badmagic rc=%d\n",tp12_prop_open(&r,bad,sizeof(bad)));
  memcpy(bad,area,sizeof(bad));bad[12]^=1;
  fprintf(out,"props badversion rc=%d\n",tp12_prop_open(&r,bad,sizeof(bad)));
  // A node link pointing past the data is refused, not followed.
  memcpy(bad,area,sizeof(bad));bad[TP12_PROP_HEADER+16]=0xff;bad[TP12_PROP_HEADER+17]=0xff;bad[TP12_PROP_HEADER+18]=0x01;
  tp12_prop_open(&r,bad,sizeof(bad));
  fprintf(out,"props badlink find=%s\n",tp12_prop_find(&r,"ro.board.platform")?"found":"(null)");}
 // Refusals: duplicate, empty segment, long value, too-long name, full area.
 {static unsigned char area[4096];struct tp12_props a;
  tp12_prop_init(&a,area,sizeof(area));tp12_prop_add(&a,"a.b","1");
  int rc=tp12_prop_add(&a,"a.b","2");fprintf(out,"props dup rc=%d error=%d\n",rc,a.error);
  const char *badnames[]={"a..b",".a","a.",""};
  for(unsigned i=0;i<4;++i){tp12_prop_init(&a,area,sizeof(area));rc=tp12_prop_add(&a,badnames[i],"1");
   fprintf(out,"props badname '%s' rc=%d error=%d\n",badnames[i],rc,a.error);}
  char longv[93];memset(longv,'x',92);longv[92]=0;
  tp12_prop_init(&a,area,sizeof(area));rc=tp12_prop_add(&a,"a.b",longv);fprintf(out,"props longvalue rc=%d error=%d\n",rc,a.error);
  longv[91]=0;tp12_prop_init(&a,area,sizeof(area));rc=tp12_prop_add(&a,"a.b",longv);
  fprintf(out,"props maxvalue rc=%d len=%zu\n",rc,strlen(tp12_prop_find(&a,"a.b")?tp12_prop_find(&a,"a.b"):""));
  char longn[100];memset(longn,'n',99);longn[99]=0;
  tp12_prop_init(&a,area,sizeof(area));rc=tp12_prop_add(&a,longn,"1");fprintf(out,"props longname rc=%d error=%d\n",rc,a.error);
  static unsigned char small[0x80+112+40];
  tp12_prop_init(&a,small,sizeof(small));rc=tp12_prop_add(&a,"ro.product.brand","Unihertz");
  fprintf(out,"props full rc=%d error=%d used=%u\n",rc,a.error,a.used);
  rc=tp12_prop_init(&a,small,100);fprintf(out,"props tiny rc=%d error=%d\n",rc,a.error);}
 // ---- teed phase helpers ----
 // Line splitting: CRLF from the pty, a split write, a control byte, an over-long line, a tail.
 {struct tp12_lines l;tp12_lines_init(&l);
  const char *a="tkcore-teec: start\r\nteed liste";const char *b="ning on /dev/tkcoredrv\r\nbell\a here\n";
  tp12_lines_feed(&l,a,strlen(a),report);fprintf(out,"lines after-a n=%u listening=%d\n",l.lines,l.listening);
  tp12_lines_feed(&l,b,strlen(b),report);fprintf(out,"lines after-b n=%u listening=%d\n",l.lines,l.listening);
  char big[TP12_TEED_LINE_MAX*2+11];memset(big,'x',sizeof(big)-1);big[sizeof(big)-1]=0;
  tp12_lines_feed(&l,big,strlen(big),report);fprintf(out,"lines big n=%u split=%u held=%zu\n",l.lines,l.split,l.len);
  tp12_lines_feed(&l,"tail",4,report);tp12_lines_flush(&l,report);
  fprintf(out,"lines flushed n=%u held=%zu\n",l.lines,l.len);tp12_lines_flush(&l,report);fprintf(out,"lines reflush n=%u\n",l.lines);}
 // Past the cap lines are counted, not logged, and readiness is still seen.
 {struct tp12_lines l;tp12_lines_init(&l);FILE *keep=out;out=fopen("/dev/null","w");
  for(unsigned i=0;i<TP12_TEED_MAX_LOGGED;++i)tp12_lines_feed(&l,"x\n",2,report);
  fclose(out);out=keep;tp12_lines_feed(&l,"teed listening on /dev/tkcoredrv\n",33,report);
  fprintf(out,"lines cap n=%u dropped=%u listening=%d\n",l.lines,l.dropped,l.listening);}
 fprintf(out,"comm tkuinit=%d nl=%d teed=%d early=%d\n",tp12_comm_is_tkuinit("tkuinit"),tp12_comm_is_tkuinit("tkuinit\n"),
  tp12_comm_is_tkuinit("teed"),tp12_comm_is_tkuinit("tkearlyinit"));
 // Readiness: exited, ready, the pipe fallback, timeout.
 {struct {const char *tag;struct tp12_teed_seen s;double t;} w[]={
   {"start",{0,0,1,0,1},0},{"listening-tkuinit",{0,1,1,1,1},5},{"ready",{0,1,0,1,1},6},
   {"no-tkuinit-no-line",{0,0,0,0,1},6},{"pty-tkuinit-gone-no-line",{0,0,0,1,1},6},{"pipe-gone",{0,0,0,1,0},6},
   {"pipe-never-seen",{0,0,0,0,0},6},{"exited",{1,1,0,1,1},6},{"timeout",{0,1,1,1,1},30},{"just-before",{0,1,1,1,1},29.9},
   {"ready-at-limit",{0,1,0,1,1},31}};
  for(unsigned i=0;i<sizeof(w)/sizeof(w[0]);++i)fprintf(out,"wait %s=%d\n",w[i].tag,tp12_teed_wait_state(&w[i].s,w[i].t));}
 fprintf(out,"stop t0=%d t2.9=%d t3=%d t3k=%d t4.9k=%d t5=%d t5k=%d\n",tp12_stop_step(0,0),tp12_stop_step(2.9,0),tp12_stop_step(3,0),
  tp12_stop_step(3,1),tp12_stop_step(4.9,1),tp12_stop_step(5,0),tp12_stop_step(5,1));
 fprintf(out,"session t19.9=%d t20=%d\n",tp12_session_expired(19.9),tp12_session_expired(20));
 fprintf(out,"fits worst=%.0f teardown=%.0f t29=%d t39=%d t39.1=%d t44=%d t90=%d\n",TP12_PHASE_WORST_SECONDS,TP12_TEARDOWN_SECONDS,
  tp12_phase_fits(29,250),tp12_phase_fits(39,250),tp12_phase_fits(39.1,250),tp12_phase_fits(44,250),tp12_phase_fits(90,250));
 fprintf(out,"protected n=%zu",TP12_PROTECTED);for(size_t i=0;i<TP12_PROTECTED;++i)fprintf(out," %s",tp12_protected[i]);fprintf(out,"\n");
 {char d[65];const char *h="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";char line[256];
  snprintf(line,sizeof(line),"part-hash name=nvcfg bytes=33554432 sha256=%s seconds=0.20",h);
  int rc=tp12_hash_digest(line,d);fprintf(out,"digest full rc=%d same=%d\n",rc,!strcmp(d,h));
  snprintf(line,sizeof(line),"part-hash name=nvcfg stopped_at_deadline=1 partial prefix_bytes=1 of=2 sha256=%s seconds=1",h);
  rc=tp12_hash_digest(line,d);fprintf(out,"digest partial rc=%d empty=%d\n",rc,!d[0]);
  rc=tp12_hash_digest("part-hash name=nvcfg not_in_gpt",d);fprintf(out,"digest none rc=%d\n",rc);
  snprintf(line,sizeof(line),"part-hash name=x sha256=%.63sZ seconds=1",h);rc=tp12_hash_digest(line,d);fprintf(out,"digest badhex rc=%d\n",rc);
  snprintf(line,sizeof(line),"part-hash name=x sha256=%s0",h);rc=tp12_hash_digest(line,d);fprintf(out,"digest long rc=%d\n",rc);
  snprintf(line,sizeof(line),"part-hash name=x sha256=%s",h);rc=tp12_hash_digest(line,d);fprintf(out,"digest end rc=%d\n",rc);}
 fclose(out);return 0;}
'''

# The legacy property area teed reads, from milestone 1 of DIAGNOSTIC_510_V12_TRIAL.md.
PLAN=ROOT/'DIAGNOSTIC_510_V12_TRIAL.md'
EXPECT_PROPS=[('ro.product.brand','Unihertz'),('ro.product.model','Titan pocket'),('ro.board.platform','mt6771'),
              ('vendor.trustkernel.fs.state','ready'),('vendor.trustkernel.log.state','enable')]
PROP_MISSES=['ro.product.device','ro.product','vendor.trustkernel.ready','ro..brand','ro.product.brand.','.ro']
# bionic's own system_properties code. The product tree has no bionic checkout, so this is the
# Boston tree's; prop_area's layout and lookup are unchanged from Android 11 for short values.
BIONIC=pocket_paths.platform_source() / 'bionic/libc'
CXX=str(Path(CLANG).parent/'clang++')

# Links bionic's prop_area.cpp and prop_info.cpp on the host. fstat is shimmed to report root,
# since map_fd_ro refuses a file not owned by uid 0 and gid 0. argv: our area, the path for the
# area bionic builds itself, then name=value pairs to add and look up, then "--", then misses.
BIONIC_TEST=r'''
#include "system_properties/prop_area.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
extern "C" int tp_fstat_root(int fd,struct stat *st){int r=::fstat(fd,st);st->st_uid=0;st->st_gid=0;return r;}
static void count(const prop_info *pi,void *c){(void)pi;++*(int *)c;}
int main(int argc,char **argv){
 int i=3;
 prop_area *built=prop_area::map_prop_area_rw(argv[2],nullptr,nullptr);
 if(!built){printf("bionic rw failed\n");return 1;}
 for(;i<argc&&strcmp(argv[i],"--");++i){char name[128];const char *eq=strchr(argv[i],'=');
  snprintf(name,sizeof(name),"%.*s",(int)(eq-argv[i]),argv[i]);
  printf("bionic add %s=%d\n",name,built->add(name,strlen(name),eq+1,strlen(eq+1)));}
 prop_area::unmap_prop_area(&built);
 prop_area *pa=prop_area::map_prop_area(argv[1]);
 printf("bionic map=%d\n",pa!=nullptr);
 if(!pa)return 1;
 for(int j=3;j<argc&&strcmp(argv[j],"--");++j){char name[128];const char *eq=strchr(argv[j],'=');
  snprintf(name,sizeof(name),"%.*s",(int)(eq-argv[j]),argv[j]);
  const prop_info *pi=pa->find(name);
  if(pi)printf("bionic find %s=%s len=%u name=%s\n",name,pi->value,(unsigned)(pi->serial.load()>>24),pi->name);
  else printf("bionic find %s=(null)\n",name);}
 for(++i;i<argc;++i)printf("bionic miss '%s'=%s\n",argv[i],pa->find(argv[i])?"found":"(null)");
 int n=0;pa->foreach(count,&n);printf("bionic foreach=%d\n",n);
 prop_area::unmap_prop_area(&pa);return 0;}
'''

def parse_props(data):
 """A reader written from bionic's prop_area.cpp: header checks as map_fd_ro, find as
 find_property and find_prop_trie_node, foreach in foreach_property order."""
 used,serial,magic,version=struct.unpack_from('<4I',data,0)
 assert magic==0x504f5250 and version==0xfc6ed0ab,(hex(magic),hex(version))
 dsize=len(data)-0x80
 def node(off):
  assert off+20<=dsize
  namelen,prop,left,right,children=struct.unpack_from('<5I',data,0x80+off)
  name=data[0x80+off+20:0x80+off+20+namelen]
  assert data[0x80+off+20+namelen]==0
  return namelen,prop,left,right,children,name
 def info(off):
  ser,=struct.unpack_from('<I',data,0x80+off)
  vlen=ser>>24
  value=data[0x80+off+4:0x80+off+4+vlen];assert data[0x80+off+4+vlen]==0
  end=data.index(b'\0',0x80+off+96)
  return value.decode(),data[0x80+off+96:end].decode(),ser
 def cmp(a,b):
  if len(a)!=len(b):return -1 if len(a)<len(b) else 1
  return (a>b)-(a<b)
 def find(name):
  cur=0
  for seg in name.encode().split(b'.'):
   if not seg:return None
   off=node(cur)[4]
   while off:
    _,_,left,right,_,nm=node(off)
    c=cmp(seg,nm)
    if c==0:break
    off=left if c<0 else right
   if not off:return None
   cur=off
  prop=node(cur)[1]
  return info(prop) if prop else None
 def foreach(off,out):
  _,prop,left,right,children,_=node(off)
  if left:foreach(left,out)
  if prop:out.append(info(prop))
  if children:foreach(children,out)
  if right:foreach(right,out)
  return out
 return {'used':used,'serial':serial,'find':find,'all':foreach(0,[]),'reserved':data[16:0x80]}

def main():
 checks=0
 header=HEADER.read_text()
 keymaster=KEYMASTER.read_text()
 tee_ioc=TEE_IOC.read_text()
 # The teed option names and the TA uuid are the ones in the saved REA, not invented here.
 for opt in ['--prot','--datapath','--sptapath','--logpath','--systapath','--rpmbdev','--proprefix']:
  assert opt in keymaster,opt;checks+=1
 assert '--rpmbdev /dev/mmcblk0rpmb --rpmbdev /dev/rpmb0' in keymaster;checks+=1
 assert '9ef77781-7bd5-4e39-965f-20f6f211f46b' in keymaster;checks+=1
 # The five ioctl constants transcribed into the header still match the kernel header's commands.
 assert '_IOWR(\'t\', 161, struct tee_cmd_io)'.replace(' ','') in tee_ioc.replace(' ','') or '_IOWR(\'t\', 161, struct tee_cmd_io)' in tee_ioc;checks+=1
 for frag in ['TEE_OPEN_SESSION_IOC','TEE_ALLOC_SHM_IOC','TEE_ALLOC_SHM_PERM_IOC','TEE_INVOKE_COMMAND_IOC','TEE_QUERY_DRV_FEATURE_IOC']:
  assert frag in tee_ioc,frag;checks+=1
 # The header pins the forbidden options and never leaves --rpmbdev or the short flags emittable.
 assert 'tp12_teed_forbidden[] = {"--rpmbdev", "--sdrpmbdev", "--prebuilt", "--nofrp", "-p", "-r"}' in header;checks+=1
 # Every forbidden long name is one of teed's own options (milestone 1's getopt table).
 plan=PLAN.read_text()
 assert 'sdrpmbdev datapath logpath systapath sptapath prot prebuilt proprefix nofrp rpmbdev' in plan;checks+=1
 # The five properties are the ones milestone 1 lists.
 for name,value in EXPECT_PROPS:
  assert f'`{name}={value}`' in plan,name
  assert f'{{"{name}", "{value}"}}' in header,name
 checks+=1
 assert header.count('0x800474b7')>=1 and '0xc01874a5' in header and '0xc01874a6' in header and '0xc03074a1' in header and '0xc03074a3' in header;checks+=1

 with tempfile.TemporaryDirectory(prefix='tp12-probes-') as tmp:
  tmp=Path(tmp)
  src=tmp/'t.c';src.write_text(C_TEST);exe=tmp/'t';outp=tmp/'out.txt'
  inc_tk=str(TKCORE/'include')
  subprocess.run(['cc','-std=gnu11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-fno-sanitize-recover=all',
                  '-I',str(HEADER.parent),'-I',inc_tk,str(src),'-o',str(exe)],check=True)
  area=tmp/'props.bin'
  subprocess.run([str(exe),str(outp),str(area)],check=True)
  lines=outp.read_text().splitlines()
  # teed builder: the clean command line is exactly the expected argv, all writable paths under root.
  argc=next(l for l in lines if l.startswith('build clean '))
  assert argc=='build clean argc=15 error=0',argc;checks+=1
  cmd=next(l for l in lines if l.startswith('cmdline clean ')).split(' ',2)[2]
  assert cmd.split(' ')==EXPECT_ARGV,cmd;checks+=1
  # No forbidden token anywhere in the command line.
  assert '--rpmbdev' not in cmd and ' -p ' not in (' '+cmd+' ') and ' -r ' not in (' '+cmd+' ');checks+=1
  # Every writable path sits under the tmpfs root; the read-only systapath does not.
  toks=cmd.split(' ')
  for flag in ['--prot','--datapath','--sptapath','--logpath']:
   for i,t in enumerate(toks):
    if t==flag: assert toks[i+1].startswith(TMPFS_ROOT+'/'),toks[i+1]
  assert toks[toks.index('--systapath')+1]=='/vendor/app/t6';checks+=1
  # A second root is honoured the same way.
  other=next(l for l in lines if l.startswith('cmdline otherroot ')).split(' ',2)[2]
  assert '--datapath /data/local/tk/fs' in other and '--rpmbdev' not in other;checks+=1
  # Bad roots are refused with no command line emitted.
  for tag in ['dotdot','relative','trailing']:
   b=next(l for l in lines if l.startswith(f'build {tag} '))
   assert b==f'build {tag} argc=-1 error=22',b;checks+=1
   assert not any(l.startswith(f'cmdline {tag} ') for l in lines);checks+=1
  # Classification.
  assert 'class rpmbdev=3 sdrpmbdev=3 prebuilt=3 nofrp=3 p=3 r=3 prot=1 datapath=1 systapath=2 proprefix=2 junk=0' in lines;checks+=1
  for opt in ['sdrpmbdev','prebuilt','nofrp']:
   assert f'add {opt} rc=-1 error=1 count=0' in lines,opt;checks+=1
  # Failing case 1: an rpmb option is refused (EPERM=1), and an unknown one (EINVAL=22).
  assert 'add rpmbdev rc=-1 error=1 count=0' in lines;checks+=1
  assert 'add p rc=-1 error=1' in lines;checks+=1
  assert 'add bogus rc=-1 error=22' in lines;checks+=1
  # Failing case 2: a path outside the tmpfs root is rejected by the guard.
  assert 'under in=1 out=0 dotdot=0 exact=0 rel=0' in lines;checks+=1
  # TEEC client success: node opened, feature query, session open, TEE success, right fd.
  ok=next(l for l in lines if l.startswith('teec ok '))
  assert ok=='teec ok rc=0 opened=1 feature=1 sent=1 err=0 result=0x00000000 origin=3 sess=11 rejected=0',ok;checks+=1
  assert 'open /dev/tkcoredrv' in lines;checks+=1
  # The ioctls issued are the feature query then the session open, as stock TEEC_InitializeContext
  # and TEEC_OpenSession issue them, and the fake driver took the envelope: a zeroed operation,
  # fd_sess -1 and origin TEEC_ORIGIN_API in, no data.
  seq=next(l for l in lines if l.startswith('teec seq '))
  assert seq=='teec seq n=2 first=0x800474b7 second=0xc03074a1 uuid_seen=1 op_seen=1 param_types=0 fd_sess=-1 origin_in=1 cmd=0 data_size=0',seq;checks+=1
  # The session carried the keymaster TA uuid; no SHM, RPMB or invoke ioctl.
  assert 'teec uuid 9ef77781-7bd5-4e39 node=966b' in lines;checks+=1
  assert not any(x in seq for x in ['0xc03074a3','0xc01874a5','0xc01874a6']);checks+=1
  assert 'teec features rc=0 feature=1 features=0x5' in lines;checks+=1
  assert 'teec featurefail rc=0 feature=0 sent=1 sess=11' in lines;checks+=1
  assert 'teec feature ioctl=0x800474b7 rc=-25 features=0x0' in lines;checks+=1
  # TEEC failures: a TEE-side non-zero result, an ioctl error, and an open error are each reported.
  assert 'teec teefail rc=-1 result=0xffff0006 origin=4 sent=1 sess=-1 err=0' in lines;checks+=1
  assert 'teec ioctlfail rc=-1 err=19 sent=1 result=0xffff0006 origin=3 sess=-1' in lines;checks+=1
  assert 'teec openfail rc=-1 err=13 opened=0' in lines;checks+=1
  # The fake driver's SHM checks: the stock-shaped request is taken, fd_shm -1 (the old client's)
  # and every other bad field are refused with EINVAL.
  assert 'kshm stock rc=0 fd=9' in lines;checks+=1
  for tag,fd in [('fd-minus1',-1),('fd-5',5),('buffer',0),('flags0',0),('dmabuf-only',0),('registered',0)]:
   assert f'kshm {tag} rc=-22 fd={fd}' in lines,tag;checks+=1
  # Its open-session checks: the client's envelope is taken, a NULL op (the old client's) and the
  # other bad envelopes are refused. fd_sess 0 is allowed, as the driver only refuses > 0.
  assert 'kopen client rc=0 sess=11' in lines and 'kopen fd-sess-0 rc=0 sess=11' in lines;checks+=1
  for tag,fd in [('op-null',-1),('uuid-null',-1),('fd-sess-1',1),('data-nosize',-1),('size-nodata',-1),('value-param',-1)]:
   assert f'kopen {tag} rc=-22 sess={fd}' in lines,tag;checks+=1
  assert 'fill err=0 origin=1 cmd=0 fd_sess=-1 uuid=1 data=1 data_size=0 reserved=0 op=1 op_zero=1' in lines;checks+=1
  assert 'kfeature null rc=-22' in lines;checks+=1
  # The transcribed driver checks are still what the 5.10 source says.
  core=(TKCORE/'core/tee_core.c').read_text();sess=(TKCORE/'core/tee_session.c').read_text();tz=(TKCORE/'armtz/tee_tz_drv.c').read_text()
  for frag in ['if ((k_shm.buffer != NULL) || (k_shm.fd_shm != 0) ||\n\t\t((k_shm.flags & tee->shm_flags) == 0) ||\n\t\t(k_shm.registered != 0)) {',
               'put_user(k_shm.fd_shm, &u_shm->fd_shm);\n\tput_user(k_shm.flags, &u_shm->flags);',
               'tee->shm_flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT | TEEC_MEM_NONSECURE;',
               'if (k_cmd.fd_sess > 0) {',
               'if ((k_cmd.op == NULL) || (k_cmd.uuid == NULL) ||\n\t\t((k_cmd.data != NULL) && (k_cmd.data_size == 0)) ||\n\t\t((k_cmd.data == NULL) && (k_cmd.data_size != 0))) {',
               'ret = tee_session_create_fd(ctx, &k_cmd);\n\tput_user(k_cmd.err, &u_cmd->err);\n\tput_user(k_cmd.origin, &u_cmd->origin);\n\tif (ret)\n\t\tgoto exit;\n\n\tput_user(k_cmd.fd_sess, &u_cmd->fd_sess);',
               'case TEE_QUERY_DRV_FEATURE_IOC:\n\t\tif (u_arg) {']:
   assert frag in core,frag;checks+=1
  # nsdrv_feature_flags is never assigned in 5.10, so the feature word is 0 there.
  assert 'static uint32_t nsdrv_feature_flags;' in core and not re.search(r'nsdrv_feature_flags\s*[|&+^-]?=[^=]',core) and core.count('nsdrv_feature_flags')==4;checks+=1
  for frag in ['cmd->origin = TEEC_ORIGIN_TEE;\n\tcmd->err = TEEC_ERROR_BAD_PARAMETERS;',
               'if (tee_context_copy_from_client(ctx, &op, cmd_io->op, sizeof(op)))',
               'if (cmd_io->uuid != NULL) {',
               'if (ret || !sess->sessid || cmd_io->err) {',
               'cmd_io->fd_sess = -1;\n\t\tgoto out;']:
   assert frag in sess,frag;checks+=1
  assert 'meta->clnt_login = 0;' in tz;checks+=1
  # The stock libteec layout the client copies, from the saved disassembly.
  lt=LIBTEEC_EVIDENCE.read_text()
  assert '6bd83cdf69836ecf557debaf5e5a6195e6c10a291869ec29ee7538a3c4fcddbe' in lt;checks+=1
  assert ' 2f60 00000000 01000000 00000000 ffffffff' in lt;checks+=1
  assert lt.count('movk\tw1, #0x74a1')==1 and 'movk\tw1, #0x74b7' in lt and 'mov\tw2, #0x118' in lt;checks+=1
  assert '      1 bl\t0x1330 <ioctl@plt>' in lt;checks+=1
  # The constants and sizes as the header pins them.
  assert 'const version=0x800474b7 ctx=0xc01874a5 ctxperm=0xc01874a6 session=0xc03074a1 invoke=0xc03074a3' in lines;checks+=1
  assert 'size cmd_io=48 shm_io=24 operation=280' in lines;checks+=1
  # Failing case 3: the session ioctl built with a wrong payload size is a different number.
  ws=next(l for l in lines if l.startswith('wrong-size '))
  assert ws=='wrong-size ioc=0xc00474a1 matches=0',ws;checks+=1
  # teed phase helpers: line splitting from the pty, readiness, limits and the hash digest.
  big='x'*200
  want=['teed: tkcore-teec: start','teed: teed listening on /dev/tkcoredrv','teed: bell? here',f'teed: {big}',f'teed: {big}','teed: '+'x'*10+'tail']
  got=[l for l in lines if l.startswith('teed: ')]
  assert got==want,got;checks+=1
  assert 'lines after-a n=1 listening=0' in lines and 'lines after-b n=3 listening=1' in lines;checks+=1
  assert 'lines big n=5 split=2 held=10' in lines and 'lines flushed n=6 held=0' in lines and 'lines reflush n=6' in lines;checks+=1
  assert 'lines cap n=401 dropped=1 listening=1' in lines;checks+=1
  assert 'comm tkuinit=1 nl=1 teed=0 early=0' in lines;checks+=1
  # 0 pending, 1 ready, 2 exited, 3 timeout.
  for tag,v in [('start',0),('listening-tkuinit',0),('ready',1),('no-tkuinit-no-line',0),('pty-tkuinit-gone-no-line',0),
                ('pipe-gone',1),('pipe-never-seen',0),('exited',2),('timeout',3),('just-before',0),('ready-at-limit',1)]:
   assert f'wait {tag}={v}' in lines,(tag,[l for l in lines if l.startswith('wait ')]);checks+=1
  assert 'stop t0=0 t2.9=0 t3=1 t3k=0 t4.9k=0 t5=2 t5k=2' in lines;checks+=1
  assert 'session t19.9=0 t20=1' in lines;checks+=1
  # Worst case 5+30+20+5+7+5 s (teardown: three 2 s umount retries plus 1 s), so with the 139 s
  # super hash the phase starts by 39 s or is skipped.
  assert 'fits worst=72 teardown=7 t29=1 t39=1 t39.1=0 t44=0 t90=0' in lines;checks+=1
  assert 'attempt < TP12_UMOUNT_TRIES' in INIT.read_text() and 'usleep(TP12_UMOUNT_WAIT_US)' in INIT.read_text();checks+=1
  assert 'protected n=6 protect1 protect2 persist nvdata nvcfg proinfo' in lines;checks+=1
  for tag,v in [('full rc=0 same=1',None),('partial rc=-1 empty=1',None),('none rc=-1',None),('badhex rc=-1',None),('long rc=-1',None),('end rc=0',None)]:
   assert f'digest {tag}' in lines,tag;checks+=1
  # The six are the stock backup's partitions.
  manifest=json.loads(MANIFEST.read_text())
  names={p['name'] for p in manifest['partitions'] if isinstance(p,dict)}
  assert {'protect1','protect2','persist','nvdata','nvcfg','proinfo'}<=names;checks+=1
  # init.c wiring: teed runs with the builder argv and an empty environment, from a client not named
  # teed, the session helper is called once, the after-pass follows the teardown, and no RPMB option.
  init=INIT.read_text()
  assert 'execve(TK_TEED_PATH, argv, envp)' in init and 'char *envp[] = {NULL};' in init and '#define TK_TEED_PATH "/vendor/bin/teed"' in init;checks+=1
  assert init.count('tp12_teec_open_session(')==1 and 'prctl(PR_SET_NAME, "tp12-teec"' in init;checks+=1
  assert init.count('tp12_teed_build(')==2;checks+=1
  assert 'rpmb' not in init.lower().replace('no rpmb option','');checks+=1
  ph=init.index('tk_teed_phase(&phase, hash_disk)');td=init.index('tk_host_teardown(&host);',ph);af=init.index('tk_protected_pass(&phase, hash_disk, "after")',td)
  assert ph<td<af;checks+=1
  # Property area, C side: built, opened, each name found, misses and corruptions refused.
  data=area.read_bytes()
  assert len(data)==128*1024;checks+=1
  b=next(l for l in lines if l.startswith('props build '))
  assert re.fullmatch(r'props build rc=0 error=0 used=\d+ size=131072',b),b;checks+=1
  assert 'props open rc=0' in lines;checks+=1
  for name,value in EXPECT_PROPS:
   assert f'props find {name}={value}' in lines,name;checks+=1
  for name in PROP_MISSES+['']:
   assert f"props miss '{name}'=(null)" in lines,name;checks+=1
  for tag in ['badmagic','badversion']:
   assert f'props {tag} rc=-1' in lines,tag;checks+=1
  assert 'props badlink find=(null)' in lines;checks+=1
  assert 'props dup rc=-1 error=17' in lines;checks+=1
  for name in ['a..b','.a','a.','']:
   assert f"props badname '{name}' rc=-1 error=22" in lines,name;checks+=1
  assert 'props longvalue rc=-1 error=22' in lines;checks+=1
  assert 'props maxvalue rc=0 len=91' in lines;checks+=1
  assert 'props longname rc=-1 error=22' in lines;checks+=1
  assert 'props full rc=-1 error=28 used=136' in lines;checks+=1
  assert 'props tiny rc=-1 error=22' in lines;checks+=1
  # Property area, read back by the Python reader written from bionic's source.
  pa=parse_props(data)
  assert int(b.split('used=')[1].split()[0])==pa['used'] and pa['serial']==0 and pa['reserved']==bytes(0x70);checks+=1
  # The root node has only its children link, the 92-byte dirty backup area is zero, and nothing
  # is written past bytes_used.
  assert data[0x80:0x80+16]==bytes(16) and data[0x80+16:0x80+20]!=bytes(4) and data[0x80+20:0x80+112]==bytes(92);checks+=1
  assert data[0x80+pa['used']:]==bytes(len(data)-0x80-pa['used']);checks+=1
  for name,value in EXPECT_PROPS:
   got=pa['find'](name)
   assert got and got[0]==value and got[1]==name and got[2]==len(value)<<24,(name,got);checks+=1
  for name in PROP_MISSES:
   assert pa['find'](name) is None,name;checks+=1
  assert sorted((n,v) for v,n,_ in pa['all'])==sorted(EXPECT_PROPS);checks+=1
  # Property area, read back by bionic's own prop_area code, and the same adds made by bionic
  # give the same bytes.
  bionic_record=None
  if (BIONIC/'system_properties/prop_area.cpp').exists():
   shim=tmp/'shim';(shim/'async_safe').mkdir(parents=True);(shim/'sys').mkdir()
   (shim/'async_safe/log.h').write_text('#pragma once\n#define ANDROID_LOG_ERROR 6\n#define async_safe_format_log(...) ((void)0)\n')
   (shim/'sys/system_properties.h').write_text('#pragma once\ntypedef struct prop_info prop_info;\n#define PROP_VALUE_MAX 92\n#define PROP_NAME_MAX 32\n')
   (shim/'fstat_root.h').write_text('#pragma once\n#include <sys/stat.h>\nextern "C" int tp_fstat_root(int, struct stat *);\n#define fstat tp_fstat_root\n')
   flags=['--target=x86_64-pc-linux-gnu','-std=c++20','-O1','-Wall','-Werror','-I',str(shim),'-I',str(BIONIC/'system_properties/include'),'-I',str(BIONIC),
          '-DXATTR_NAME_SELINUX="security.selinux"']
   objs=[]
   for src_name in ['prop_area.cpp','prop_info.cpp']:
    obj=tmp/(src_name+'.o');objs.append(str(obj))
    subprocess.run([CXX,*flags,'-include',str(shim/'fstat_root.h'),'-c',str(BIONIC/'system_properties'/src_name),'-o',str(obj)],check=True)
   bsrc=tmp/'bionic.cpp';bsrc.write_text(BIONIC_TEST);bexe=tmp/'bionic'
   subprocess.run([CXX,*flags,str(bsrc),*objs,'-o',str(bexe)],check=True)
   theirs=tmp/'bionic-props.bin'
   # map_fd_ro refuses group or other write; init writes the file 0444.
   area.chmod(0o444)
   r=subprocess.run([str(bexe),str(area),str(theirs),*[f'{n}={v}' for n,v in EXPECT_PROPS],'--',*PROP_MISSES],capture_output=True,text=True)
   bl=r.stdout.splitlines()
   assert r.returncode==0,r.stdout+r.stderr
   assert 'bionic map=1' in bl,bl;checks+=1
   for name,value in EXPECT_PROPS:
    assert f'bionic add {name}=1' in bl,name
    assert f'bionic find {name}={value} len={len(value)} name={name}' in bl,(name,bl);checks+=1
   for name in PROP_MISSES:
    assert f"bionic miss '{name}'=(null)" in bl,name;checks+=1
   assert 'bionic foreach=5' in bl;checks+=1
   assert theirs.read_bytes()==data,'bionic-built area differs';checks+=1
   bionic_record={'prop_area_sha256':hashlib.sha256((BIONIC/'system_properties/prop_area.cpp').read_bytes()).hexdigest(),
                  'area_sha256':hashlib.sha256(data).hexdigest()}
  else:
   print('bionic source not found; bionic link test skipped')
  # The static asserts in probes.h compile for ARM32 and ARM64 too (the probe runs on the device).
  sysroot=str(Path(CLANG).parent.parent/'sysroot')
  arm=tmp/'arm.c';arm.write_text('#include "probes.h"\nint main(void){return 0;}\n')
  for target in ['aarch64-linux-android30','armv7a-linux-androideabi30']:
   subprocess.run([CLANG,'--target='+target,'--sysroot='+sysroot,'-fsyntax-only','-std=gnu11',
                   '-I',str(HEADER.parent),'-I',inc_tk,str(arm)],check=True)
   checks+=1
 record={'checks':checks,'sanitizers':['address','undefined'],
         'header_sha256':hashlib.sha256(HEADER.read_bytes()).hexdigest(),
         'init_sha256':hashlib.sha256(INIT.read_bytes()).hexdigest(),
         'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'tee_ioc_sha256':hashlib.sha256(TEE_IOC.read_bytes()).hexdigest(),
         'tee_client_api_sha256':hashlib.sha256(TEE_API.read_bytes()).hexdigest(),
         'keymaster_evidence_sha256':hashlib.sha256(KEYMASTER.read_bytes()).hexdigest(),
         'libteec_evidence_sha256':hashlib.sha256(LIBTEEC_EVIDENCE.read_bytes()).hexdigest(),
         'bionic_link':bionic_record,
         'device_accessed':False,
         'limits':['Host x86-64 build of the helpers plus ARM32/ARM64 syntax-only; the device init is built separately and not run here',
                   'The TEEC client runs against a fake driver through the callback ops, not /dev/tkcoredrv; the fake runs the transcribed 5.10 checks of tee_do_shm_alloc, tee_do_create_session and _init_tee_cmd; whether the session opens on 5.10 and the TEE result are device-only',
                   'The teed builder only lays out the command line; the init hosting phase (mounts, tmpfs, symlinks, the property file) and the teed run, session open and protected re-hash are compiled here but run only on the phone; only their pure helpers (line splitting, readiness, step limits, digest parsing) are run on the host',
                   'The property area is read back by a Python reader from bionic source and by bionic prop_area.cpp linked on the host; the bionic tree is the Boston (Android 16) one, as the product tree has none; whether the phone libc maps it is device-only',
                   'The teed option names and the TA uuid are transcribed from the saved REA of teed 25bb4975 (trustkernel-keymaster-5.10.md); teed is not run or disassembled here']}
 (ROOT/'evidence/kernel-upgrade/diagnostic-probes-check-v12.json').write_text(json.dumps(record,indent=2)+'\n')
 print(f'{checks} v12 probe helper checks passed under ASan/UBSan plus ARM32/ARM64 compile; no device access')
if __name__=='__main__':main()

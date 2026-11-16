#!/usr/bin/env python3
"""Compile actual pstore guard/legacy registration against synthetic OF metadata."""
import pocket_paths
import hashlib,json,os,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
OUT=pocket_paths.build_root()/'artifacts/diagnostic-5.10-v2/pstore-guard-check'
def function(source,name):
 m=re.search(r'^static (?:inline )?(?:bool|int|void)(?: __init)? '+name+r'\(',source,re.M);assert m,name
 start=source.index('{',m.start());end=start+1;depth=1
 while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[m.start():end]
def main():
 src=ROOT/'tools/kernel-source/upgrade-5.10/fs/pstore/ram.c';header=src.with_name('ram-pocket-diagnostic.h');text=src.read_text();probe=text[text.index('static int ramoops_probe('):]
 assert probe.index('ramoops_pocket_guard(dev, pdata)')<probe.index('ramoops_init_przs(')
 code=r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#define __init
#define IS_ERR(p) ((intptr_t)(p)<0 && (intptr_t)(p)>-4096)
#define PTR_ERR(p) ((intptr_t)(p))
#define KMSG_DUMP_OOPS 2
#define KMSG_DUMP_PANIC 1
#define RAMOOPS_FLAG_FTRACE_PER_CPU 1
#define pr_info(...) ((void)0)
#define dev_err(...) ((void)0)
typedef uint64_t u64;typedef uint32_t u32;
struct ramoops_platform_data {u64 mem_address; unsigned long mem_size,record_size,console_size,ftrace_size,pmsg_size; unsigned mem_type,flags,max_reason;struct {int ecc_size;} ecc_info;};
#include "ram-pocket-diagnostic.h"
struct device_node {bool diagnostic,matching,available,no_map,reusable,ranges;int refs,address_error,prop_error,range_length;u32 ac,sc;u64 start,size;};
struct resource {u64 start,end;};
struct device {struct device_node *of_node;};
struct platform_device {int unused;};
static struct device_node parent,children[3],profile;
static bool parent_exists,profile_exists,registration_fails;
static unsigned child_count,registrations;
static struct ramoops_platform_data registered;
static struct platform_device marker,*dummy;
static unsigned long mem_size=0xe0000,record_size=0x1000,ramoops_console_size=0x40000,ramoops_ftrace_size=0x1000,ramoops_pmsg_size=0x10000;
static unsigned long long mem_address=0x54410000ULL;
static unsigned mem_type;
static int ramoops_max_reason=-1,ramoops_dump_oops=-1,ramoops_ecc;
static struct device_node *dev_of_node(struct device *d) {return d->of_node;}
static bool of_device_is_compatible(struct device_node *n,const char *s) {
 if(!n)return false;
 if(!strcmp(s,"unihertz,titan-pocket-ramoops-diagnostic"))return n->diagnostic;
 assert(!strcmp(s,"mediatek,pstore"));return n->matching;
}
static struct device_node *of_find_node_by_path(const char *s) {
 assert(!strcmp(s,"/reserved-memory"));if(!parent_exists)return NULL;parent.refs++;return &parent;
}
static struct device_node *of_find_compatible_node(void *a,void *b,const char *s) {
 assert(!a&&!b&&!strcmp(s,"unihertz,titan-pocket-ramoops-diagnostic"));if(!profile_exists)return NULL;profile.refs++;return &profile;
}
static void of_node_put(struct device_node *n) {if(n){assert(n->refs>0);n->refs--;}}
static bool of_device_is_available(struct device_node *n) {return n->available;}
static int of_property_read_u32(struct device_node *n,const char *s,u32 *value) {
 assert(n==&parent);if(n->prop_error)return n->prop_error;
 if(!strcmp(s,"#address-cells"))*value=n->ac;else {assert(!strcmp(s,"#size-cells"));*value=n->sc;}return 0;
}
static void *of_find_property(struct device_node *n,const char *s,int *length) {
 assert(n==&parent&&!strcmp(s,"ranges"));*length=n->range_length;return n->ranges?n:NULL;
}
static struct device_node *next_available(struct device_node *p,struct device_node *previous) {
 assert(p==&parent);unsigned first=previous?(unsigned)(previous-children)+1:0;of_node_put(previous);
 for(unsigned i=first;i<child_count;i++)if(children[i].available){children[i].refs++;return &children[i];}return NULL;
}
#define for_each_available_child_of_node(p,n) for(n=next_available(p,NULL);n;n=next_available(p,n))
static int of_address_to_resource(struct device_node *n,int index,struct resource *r) {
 assert(index==0);if(n->address_error)return n->address_error;r->start=n->start;r->end=n->start+n->size-1;return 0;
}
static u64 resource_size(struct resource *r) {return r->end-r->start+1;}
static bool of_property_read_bool(struct device_node *n,const char *s) {
 if(!strcmp(s,"no-map"))return n->no_map;assert(!strcmp(s,"reusable"));return n->reusable;
}
static struct platform_device *platform_device_register_data(void *p,const char *name,int id,void *data,size_t size) {
 assert(!p&&!strcmp(name,"ramoops")&&id==-1&&size==sizeof(registered));registrations++;registered=*(struct ramoops_platform_data*)data;return registration_fails?(void*)(intptr_t)-ENOMEM:&marker;
}
'''
 for name in ['ramoops_pocket_guard','ramoops_pocket_skip_dummy','ramoops_register_dummy']:code+=function(text,name)+'\n'
 code+=r'''
static struct ramoops_platform_data good(void) {return (struct ramoops_platform_data){.mem_address=0x54410000,.mem_size=0x8f000,.record_size=0x1000,.console_size=0x40000};}
static void reset(void) {
 parent=(struct device_node){.available=true,.ranges=true,.ac=2,.sc=2};profile=(struct device_node){.diagnostic=true};
 memset(children,0,sizeof(children));children[0]=(struct device_node){.available=true,.matching=true,.no_map=true,.start=0x54410000,.size=0xe0000};
 child_count=1;parent_exists=true;profile_exists=true;registrations=0;dummy=NULL;registration_fails=false;mem_size=0xe0000;
}
static void refs_zero(void) {assert(!parent.refs&&!profile.refs);for(unsigned i=0;i<3;i++)assert(!children[i].refs);}
int main(void) {
 unsigned cases=0;struct device device={&profile};struct ramoops_platform_data data=good();
 const u64 bad[]={0,1,0x1000,0x40000,0x8f000,0xe0000,0x54410000,0x54410001,UINT64_MAX,UINT64_MAX-0xe0000};
 for(unsigned field=0;field<10;field++)for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
  reset();data=good();u64 v=bad[i];
  switch(field){case 0:data.mem_address=v;break;case 1:data.mem_size=v;break;case 2:data.record_size=v;break;case 3:data.console_size=v;break;case 4:data.ftrace_size=v;break;case 5:data.pmsg_size=v;break;case 6:data.mem_type=(unsigned)v;break;case 7:data.flags=(unsigned)v;break;case 8:data.ecc_info.ecc_size=(int)v;break;default:break;}
  bool expected=data.mem_address==0x54410000 && data.mem_size==0x8f000 && data.record_size==0x1000 && data.console_size==0x40000 && !data.ftrace_size && !data.pmsg_size && !data.mem_type && !data.flags && !data.ecc_info.ecc_size;
  assert(ramoops_pocket_layout_ok(&data)==expected);assert(ramoops_pocket_guard(&device,&data)==(expected?0:-EINVAL));refs_zero();cases++;
 }
 for(unsigned kind=0;kind<15;kind++) {
  reset();data=good();int expected=-EINVAL;
  switch(kind){case 0:expected=0;break;case 1:parent_exists=false;expected=-ENODEV;break;case 2:parent.available=false;break;case 3:parent.ac=1;break;case 4:parent.sc=1;break;case 5:parent.ranges=false;break;case 6:parent.range_length=4;break;case 7:parent.prop_error=-EIO;break;case 8:child_count=0;break;case 9:children[0].available=false;break;case 10:children[0].matching=false;break;case 11:children[0].no_map=false;break;case 12:children[0].reusable=true;break;case 13:children[0].address_error=-EIO;break;case 14:child_count=2;children[1]=children[0];break;}
  assert(ramoops_pocket_guard(&device,&data)==expected);refs_zero();cases++;
 }
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++)for(unsigned j=0;j<sizeof(bad)/sizeof(bad[0]);j++)for(unsigned bits=0;bits<4;bits++) {
  reset();data=good();children[0].start=bad[i];children[0].size=bad[j];children[0].no_map=bits&1;children[0].reusable=bits&2;
  bool expected=bad[i]==0x54410000 && bad[j]==0xe0000 && bits==1;assert(ramoops_pocket_guard(&device,&data)==(expected?0:-EINVAL));refs_zero();cases++;
 }
 reset();profile.diagnostic=false;parent_exists=false;data=good();assert(ramoops_pocket_guard(&device,&data)==0);cases++;
 for(unsigned present=0;present<2;present++)for(unsigned size=0;size<2;size++)for(unsigned fail=0;fail<2;fail++) {
  reset();profile_exists=present;mem_size=size?0xe0000:0;registration_fails=fail;ramoops_register_dummy();assert(registrations==((!present&&size)?1U:0U));
  if(registrations){assert(registered.mem_size==0xe0000&&registered.console_size==0x40000&&registered.ftrace_size==0x1000&&registered.pmsg_size==0x10000);assert(dummy==(fail?NULL:&marker));}else assert(!dummy);refs_zero();cases++;
 }
 printf("%u actual-guard, reservation, reference and legacy-bypass cases passed\n",cases);
}
'''
 OUT.mkdir(parents=True,exist_ok=True);c=OUT/'check.c';c.write_text(code);sdk=Path(os.environ.get('ANDROID_SDK_ROOT',str(Path.home()/'Android/Sdk')));clang=sdk/'ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin/clang';binary=OUT/'check'
 subprocess.run([str(clang),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(src.parent),str(c),'-o',str(binary)],check=True)
 p=subprocess.run([str(binary)],capture_output=True,text=True,check=True);assert 'runtime error:' not in p.stderr and 'Sanitizer' not in p.stderr
 record={'result':p.stdout.strip(),'inputs':{str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for f in [src,header,Path(__file__)]},'source_guard_before_mapping':True,'device_accessed':False,'limits':['OF/MMIO metadata mocked; no physical RAM mapping or target code executed','Fresh LK reservation declaration checked; cache behavior, retention and stock readback remain hardware gates','Logs begin after backend registration; earlier faults may leave nothing']};(ROOT/'evidence/kernel-upgrade/ramoops-pocket-guard.json').write_text(json.dumps(record,indent=2)+'\n');print(p.stdout,end='')
if __name__=='__main__':main()

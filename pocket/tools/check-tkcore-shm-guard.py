#!/usr/bin/env python3
"""Exercise the actual diagnostic ownership guard with metadata-only host mocks."""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
path=ROOT/'tools/kernel-source/upgrade-5.10/drivers/misc/mediatek/tkcore/armtz/tee_tz_drv.c'
body=path.read_text().split('/* Overflow-safe overlap of a memblock region',1)[1].split('\n#endif',1)[0]
body='/*'+body
prefix=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
typedef uint64_t phys_addr_t;
struct device_node {int dummy;};struct device_node nodes[2];
struct memblock_region {uint64_t base,size;unsigned flags;} memory[3],reserved[2];
struct reserved_mem {uint64_t base,size;};
struct resource {uint64_t start,end;};
static struct resource resource_data;static struct reserved_mem record_data;
static unsigned count,refs,puts;static bool enabled,nomap,has_record;static int address_error;
static const char *last_message;
#define for_each_compatible_node(n,a,b) for(n=nodes;n<nodes+count;n++)
#define for_each_mem_region(r) for(r=memory;r<memory+3;r++)
#define for_each_reserved_mem_region(r) for(r=reserved;r<reserved+2;r++)
static bool memblock_is_nomap(struct memblock_region*m){return m->flags&4;}
static struct device_node *of_node_get(struct device_node*n){refs++;return n;}
static void of_node_put(struct device_node*n){if(n)puts++;}
static bool of_device_is_available(struct device_node*n){assert(n);return enabled;}
static bool of_property_read_bool(struct device_node*n,const char*p){assert(n&&!strcmp(p,"no-map"));return nomap;}
static int of_address_to_resource(struct device_node*n,int idx,struct resource*r){assert(n&&!idx);*r=resource_data;return address_error;}
static struct reserved_mem *of_reserved_mem_lookup(struct device_node*n){assert(n);return has_record?&record_data:NULL;}
#define resource_size(r) ((r)->end-(r)->start+1)
static void capture(const char*fmt,...){va_list a;va_start(a,fmt);if(strstr(fmt,"failed: %s"))last_message=va_arg(a,const char*);va_end(a);}
static void info(const char*fmt,...){(void)fmt;}
#define pr_err capture
#define pr_info info
'''
main=r'''
#define T 0xfdc00000ULL
#define R 0x2400000ULL
static void reset(void){count=1;refs=puts=0;enabled=nomap=has_record=true;address_error=0;last_message=NULL;
 resource_data.start=T;resource_data.end=T+R-1;record_data=(struct reserved_mem){T,R};
 memory[0]=(struct memblock_region){0x40000000,T-0x40000000,0};memory[1]=(struct memblock_region){T,R,4};memory[2]=(struct memblock_region){T+R,0xc0000000,0};
 reserved[0]=(struct memblock_region){0x54400000,0x10000,0};reserved[1]=(struct memblock_region){0,0,0};}
static bool check(uint64_t b,uint64_t s){bool v=diagnostic_shm_owned(b,s);assert(refs==puts);assert(v==!last_message);return v;}
static void reject(uint64_t b,uint64_t s,const char*why){assert(!check(b,s));assert(!strcmp(last_message,why));}
#define P 0xffc28000ULL
#define S 0x3d8000ULL
int main(void){
reset();assert(check(P,S));
reset();memory[1]=(struct memblock_region){0,0,0};assert(check(P,S));
reset();memory[1].size=0x1000;memory[2]=(struct memblock_region){T+0x1000,R-0x1000,4};assert(check(P,S));
reset();count=0;reject(P,S,"exactly one mediatek,tee-reserved node");
reset();count=2;reject(P,S,"exactly one mediatek,tee-reserved node");
reset();enabled=false;reject(P,S,"TEE reservation node available");
reset();nomap=false;reject(P,S,"TEE reservation has no-map");
reset();address_error=-1;reject(P,S,"TEE reservation reg readable");
reset();has_record=false;reject(P,S,"early reserved-memory record matches reg");
reset();record_data.size-=0x1000;reject(P,S,"early reserved-memory record matches reg");
reset();record_data.base+=0x1000;reject(P,S,"early reserved-memory record matches reg");
reset();reject(P,0,"SHM range valid");
reset();reject(UINT64_MAX-0xfff,0x2000,"SHM range valid");
reset();reject(T-0x1000,S,"SHM inside TEE reservation");
reset();reject(P+0x1000,S,"SHM inside TEE reservation");
reset();reject(P+0x1000,S-0x1000,"SHM matches evidenced TEE layout");
reset();reject(P-0x1000,S,"SHM matches evidenced TEE layout");
reset();memory[1].flags=0;reject(P,S,"TEE reservation absent from mapped memory");
reset();memory[1]=(struct memblock_region){T,0x1000,0};memory[2].base=T+0x1000;memory[2].size=R-0x1000;memory[2].flags=4;reject(P,S,"TEE reservation absent from mapped memory");
reset();memory[0].size+=0x1000;reject(P,S,"TEE reservation absent from mapped memory");
reset();memory[2].base-=1;reject(P,S,"TEE reservation absent from mapped memory");
reset();reserved[1]=(struct memblock_region){T+R-1,1,0};reject(P,S,"TEE reservation absent from memblock.reserved");
reset();reserved[1]=(struct memblock_region){0x40000000,T-0x40000000+1,0};reject(P,S,"TEE reservation absent from memblock.reserved");
reset();reserved[1]=(struct memblock_region){T+R,0x1000,0};assert(check(P,S));
reset();resource_data.start=UINT64_MAX-R+1;resource_data.end=UINT64_MAX;record_data.base=resource_data.start;reject(UINT64_MAX-S+1,S,"TEE reservation range valid");
reset();resource_data.start=0x80000000;resource_data.end=0x80000000+R-1;record_data.base=0x80000000;memory[0].size=0x40000000;memory[1].base=0x80000000;memory[2].base=0x80000000+R;assert(check(0x82028000,S));
return 0;}
'''
with tempfile.TemporaryDirectory(prefix='tkcore-shm-check-') as tmp:
 p=Path(tmp)/'check.c';exe=Path(tmp)/'check';p.write_text(prefix+body+main)
 subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print(json.dumps({'actual_guard_tested':True,'scenarios':26,'device_access':False,'sanitizers':['address','undefined'],'driver_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}))

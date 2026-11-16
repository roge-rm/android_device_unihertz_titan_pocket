#!/usr/bin/env python3
"""Compare actual old/new ramoops allocation and console readers on the host."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
OLD = ROOT / 'tools/kernel-source/some00/linux-unihertz-titan-pocket-4348b016b9ed41d2a8e4a77e08be72b24cc269ad/fs/pstore'
NEW = ROOT / 'tools/kernel-source/upgrade-5.10/fs/pstore'


def function(text, name):
    match = re.search(r'^(?:static )?(?:int|void) ' + name + r'\(', text, re.M)
    assert match, name
    start = match.start()
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def main():
    layout_path = ROOT / 'evidence/kernel-upgrade/pstore-review/layout.json'
    layout = json.loads(layout_path.read_text())
    v = layout['stock_parameters']
    code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef uint32_t u32;
typedef uint64_t phys_addr_t;
typedef struct { int counter; } atomic_t;
#define GFP_KERNEL 0
#define ALIGN_DOWN(x,a) ((x) & ~((a)-1))
#define IS_ERR(p) ((uintptr_t)(p) > (uintptr_t)-4096)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define PRZ_FLAG_ZAP_OLD 1
#define kcalloc(n,s,g) calloc((n),(s))
#define kfree free
#define kmalloc(n,g) malloc(n)
#define memcpy_fromio memcpy
struct device { int unused; };
struct ramoops_context {
    phys_addr_t phys_addr; unsigned long size; unsigned memtype;
    unsigned ecc_info; size_t console_size, ftrace_size, pmsg_size;
};
static void dev_err(struct device *dev, const char *format, ...) { (void)dev; (void)format; }
static char *kasprintf(int flags, const char *format, ...) {
    (void)flags; char *out = NULL; va_list args; va_start(args,format);
    assert(vasprintf(&out,format,args)>=0); va_end(args); return out;
}
static void pr_err(const char *s) { (void)s; assert(0); }
'''
    old_core, new_core = (OLD / 'ram_core.c').read_text(), (NEW / 'ram_core.c').read_text()
    for label, source in [('stock', old_core), ('upgrade', new_core)]:
        header = re.search(r'struct persistent_ram_buffer \{.*?\n\};', source, re.S).group(0)
        assert all(field in header for field in ['sig;', 'start;', 'size;', 'data['])
        assert '#define PERSISTENT_RAM_SIG (0x43474244)' in source
        if label == 'stock':
            code += header.replace('persistent_ram_buffer', 'stock_buffer') + '\n'
        else:
            code += header + '\n'
    code += r'''
_Static_assert(sizeof(struct stock_buffer)==12,"stock header");
_Static_assert(sizeof(struct persistent_ram_buffer)==12,"upgrade header");
_Static_assert(offsetof(struct stock_buffer,data)==12,"stock payload offset");
_Static_assert(offsetof(struct persistent_ram_buffer,data)==12,"upgrade payload offset");
struct persistent_ram_zone {
    phys_addr_t addr; size_t size; u32 sig, flags; int type;
    struct persistent_ram_buffer *buffer;
    char *old_log; size_t old_log_size;
};
static struct persistent_ram_zone *allocated[256];
static unsigned allocations;
static struct persistent_ram_zone *persistent_ram_new(phys_addr_t addr, size_t size,
        u32 sig, void *ecc, unsigned memtype, u32 flags, ...) {
    (void)ecc; assert(memtype==0 && sig==0 && allocations<256);
    struct persistent_ram_zone *zone = calloc(1,sizeof(*zone)); assert(zone);
    zone->addr=addr; zone->size=size; zone->sig=sig; zone->flags=flags;
    allocated[allocations++]=zone; return zone;
}
static void persistent_ram_free(struct persistent_ram_zone *zone) { free(zone); }
static void persistent_ram_zap(struct persistent_ram_zone *zone) { (void)zone; }
static int pstore_name_to_type(const char *name) { (void)name; return 0; }
static size_t buffer_size(struct persistent_ram_zone *zone) { return zone->buffer->size.counter; }
static size_t buffer_start(struct persistent_ram_zone *zone) { return zone->buffer->start.counter; }
static void persistent_ram_ecc_old(struct persistent_ram_zone *zone) { (void)zone; }
static void persistent_ram_free_old(struct persistent_ram_zone *zone) {
    free(zone->old_log); zone->old_log=NULL; zone->old_log_size=0;
}
'''
    expressions = {}
    for label, directory in [('stock', OLD), ('upgrade', NEW)]:
        source = (directory / 'ram.c').read_text()
        for name in ['ramoops_init_przs', 'ramoops_init_prz']:
            helper = function(source, name).replace(name + '(', label + '_' + name + '(')
            code += helper + '\n'
        core = (directory / 'ram_core.c').read_text()
        code += function(core, 'persistent_ram_save_old').replace(
            'void persistent_ram_save_old(', 'static void ' + label + '_save_old(') + '\n'
        expressions[label] = re.search(r'dump_mem_sz = (.*?);', source, re.S).group(1)
    code += '\n#define BASE ' + str(v['mem_address']) + 'ULL\n'
    code += '#define FULL ' + str(v['mem_size']) + 'UL\n'
    code += '#define CONSOLE ' + str(v['console_size']) + 'UL\n'
    code += '#define PREFIX ' + str(layout['prefix']['bytes']) + 'UL\n'
    code += '#define CONSOLE_BASE ' + str(layout['stock_regions'][1]['base']) + 'ULL\n'
    code += r'''
static void layout_case(unsigned kind) {
    struct device dev = {0};
    struct ramoops_context state = {.phys_addr=BASE, .size=kind==1 ? PREFIX : FULL,
       .console_size=CONSOLE, .ftrace_size=kind==1 ? 0 : 4096, .pmsg_size=kind==1 ? 0 : 65536};
    struct ramoops_context *cxt=&state;
    struct persistent_ram_zone **dumps=NULL, **ftraces=NULL, *console=NULL, *bconsole=NULL, *pmsg=NULL;
    unsigned count=0, trace_count=1;
    phys_addr_t address=BASE;
    size_t dump_mem_sz;
    allocations=0;
    if (kind==0) {
'''
    code += 'dump_mem_sz = ' + expressions['stock'] + ';\n'
    code += r'''
        assert(!stock_ramoops_init_przs("dump",&dev,cxt,&dumps,&address,dump_mem_sz,4096,&count,0,0));
        assert(!stock_ramoops_init_prz("console",&dev,cxt,&console,&address,CONSOLE,0));
        assert(!stock_ramoops_init_prz("bconsole",&dev,cxt,&bconsole,&address,CONSOLE,0));
        assert(!stock_ramoops_init_przs("ftrace",&dev,cxt,&ftraces,&address,cxt->ftrace_size,-1,&trace_count,0,0));
        assert(!stock_ramoops_init_prz("pmsg",&dev,cxt,&pmsg,&address,cxt->pmsg_size,0));
    } else {
'''
    code += 'dump_mem_sz = ' + expressions['upgrade'] + ';\n'
    code += r'''
        assert(!upgrade_ramoops_init_przs("dmesg",&dev,cxt,&dumps,&address,dump_mem_sz,4096,&count,0,0));
        assert(!upgrade_ramoops_init_prz("console",&dev,cxt,&console,&address,CONSOLE,0));
        assert(!upgrade_ramoops_init_przs("ftrace",&dev,cxt,&ftraces,&address,cxt->ftrace_size,-1,&trace_count,0,0));
        assert(!upgrade_ramoops_init_prz("pmsg",&dev,cxt,&pmsg,&address,cxt->pmsg_size,0));
    }
    assert(console && console->size==CONSOLE && address==BASE+cxt->size);
    if (kind<2) {
        assert(count==79 && console->addr==CONSOLE_BASE);
        for (unsigned i=0;i<count;i++) assert(dumps[i]->addr==BASE+i*4096 && dumps[i]->size==4096);
    } else assert(console->addr==CONSOLE_BASE+CONSOLE); // Naive full region is incompatible.
    for (unsigned i=0;i<allocations;i++) persistent_ram_free(allocated[i]);
    free(dumps); free(ftraces);
}
static unsigned readers;
static void ring_case(unsigned size, unsigned start) {
    struct persistent_ram_buffer *buffer=calloc(1,sizeof(*buffer)+size); assert(buffer);
    buffer->sig=0x43474244; buffer->start.counter=start; buffer->size.counter=size;
    for(unsigned i=0;i<size;i++) buffer->data[i]=(i*37+5)&255;
    for(unsigned reader=0;reader<2;reader++) {
        struct persistent_ram_zone zone={.buffer=buffer};
        if(reader) upgrade_save_old(&zone); else stock_save_old(&zone);
        assert(zone.old_log_size==size);
        for(unsigned i=0;i<size;i++) assert((unsigned char)zone.old_log[i]==buffer->data[(start+i)%size]);
        persistent_ram_free_old(&zone); readers++;
    }
    free(buffer);
}
int main(void) {
    for(unsigned kind=0;kind<3;kind++) layout_case(kind);
    struct device dev={0};
    struct ramoops_context state={.phys_addr=BASE,.size=16};
    phys_addr_t address=BASE;
    struct persistent_ram_zone *zone=NULL;
    assert(upgrade_ramoops_init_prz("console",&dev,&state,&zone,&address,CONSOLE,0)==-ENOMEM);
    for(unsigned size=0;size<=64;size++) for(unsigned start=0;start<=size;start++) ring_case(size,start);
    const unsigned positions[]={0,1,(CONSOLE-12)/2,CONSOLE-13,CONSOLE-12};
    for(unsigned i=0;i<5;i++) ring_case(CONSOLE-12,positions[i]);
    printf("4 allocation/layout cases and %u actual-reader cases passed; headers are 12 bytes\n",readers);
}
'''
    out = ROOT / 'artifacts/kernel-upgrade/pstore-format-check'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'check.c').write_text(code)
    clang = str(pocket_paths.ndk_bin() / 'clang')
    # Match the kernel's existing signed-loop comparison warning policy while
    # retaining the extracted functions byte-for-byte.
    subprocess.run([clang, '-Wall', '-Wextra', '-Werror', '-Wno-sign-compare', '-fsanitize=address,undefined',
                    str(out / 'check.c'), '-o', str(out / 'check')], check=True)
    checked = subprocess.run([str(out / 'check')], capture_output=True, text=True)
    if checked.returncode or 'runtime error:' in checked.stderr or 'AddressSanitizer' in checked.stderr:
        raise RuntimeError(checked.stderr)
    inputs = [layout_path, OLD/'ram.c', NEW/'ram.c', OLD/'ram_core.c', NEW/'ram_core.c']
    record = {'result': checked.stdout.strip(),
              'inputs': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},
              'limits': ['Actual allocation and console-reader functions with mocked RAM allocation/I/O',
                         'Valid ring states only; header acceptance, cache/MMIO ordering and ECC are not emulated',
                         'No firmware, kernel or phone execution; warm-reset retention/readback remains untested']}
    (ROOT / 'evidence/kernel-upgrade/pstore-review/format-check.json').write_text(json.dumps(record, indent=2)+'\n')
    print(checked.stdout, end='')


if __name__ == '__main__':
    main()

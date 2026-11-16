#!/usr/bin/env python3
"""Host-test the v8 probe helpers (SHA-256, GPT, partition hashing, memreserve, ACM
line hashing, I2C target table) under ASan/UBSan against Python references, and the stock-side hash
tool's parser. Synthetic data only; never accesses a phone."""
import hashlib,json,os,random,runpy,struct,subprocess,tempfile,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
HEADER=ROOT/'kernel-upgrade/diagnostic-probe-v8/probes.h'
TOOL=ROOT/'tools/pocket-partition-hashes.py'
LBS=4096

def gpt_disk(path,parts,blocks,fill=True):
 """Writes a sparse disk with a protective MBR and primary GPT at LBA 1."""
 entries=bytearray(128*128)
 for i,(name,first,last) in enumerate(parts):
  e=struct.pack('<16s16sQQQ',b'\x11'*16,bytes([i+1])*16,first,last,0)+name.encode('utf-16-le').ljust(72,b'\0')
  entries[i*128:(i+1)*128]=e
 header=bytearray(struct.pack('<8sIIIIQQQQ16sQIII',b'EFI PART',0x10000,92,0,0,1,blocks-1,6,blocks-6,b'\x22'*16,2,128,128,zlib.crc32(entries)))
 struct.pack_into('<I',header,16,zlib.crc32(header[:92]))
 with open(path,'wb') as f:
  f.truncate(blocks*LBS);f.seek(510);f.write(b'\x55\xaa');f.seek(LBS);f.write(header);f.seek(2*LBS);f.write(entries)
  rng=random.Random(8)
  for _,first,last in (parts if fill else []):
   f.seek(first*LBS);f.write(rng.randbytes((last-first+1)*LBS))

C_TEST=r'''
#include "probes.h"
#include <assert.h>
static FILE *out;
static void report(const char *m){fprintf(out,"%s\n",m);}
int main(int argc,char **argv){
 assert(argc==6);
 out=fopen(argv[2],"w");assert(out);
 int fd=open(argv[1],O_RDONLY);assert(fd>=0);
 struct tp8_gpt_part parts[TP8_GPT_MAX_ENTRIES];const char *why="";
 int count=tp8_gpt_read(fd,4096,atoll(argv[3]),parts,TP8_GPT_MAX_ENTRIES,&why);
 fprintf(out,"gpt count=%d why=%s\n",count,why);
 for(int i=0;i<count;++i){
  fprintf(out,"part %s %u %llu %llu\n",parts[i].name,parts[i].index,(unsigned long long)parts[i].first,(unsigned long long)parts[i].last);
  tp8_hash_range(fd,parts[i].name,parts[i].first*4096,(parts[i].last-parts[i].first+1)*4096,tp8_now()+600,report);
 }
 // An expired deadline stops before any read and still logs a prefix hash.
 if(count>0)tp8_hash_range(fd,"expired",parts[0].first*4096,4096,tp8_now()-1,report);
 // A range past the end ends in a short-read error, not a hang.
 tp8_hash_range(fd,"past-end",(uint64_t)atoll(argv[3])*4096-8192,1<<20,tp8_now()+60,report);
 close(fd);
 // Corrupt GPT: flip one header byte through a copy.
 fd=open(argv[4],O_RDONLY);assert(fd>=0);
 count=tp8_gpt_read(fd,4096,atoll(argv[3]),parts,TP8_GPT_MAX_ENTRIES,&why);fprintf(out,"corrupt count=%d why=%s\n",count,why);close(fd);
 // FDT memreserve.
 unsigned char fdt[256]={0};uint64_t b[4],s[4];
 fdt[0]=0xd0;fdt[1]=0x0d;fdt[2]=0xfe;fdt[3]=0xed;fdt[7]=200;fdt[19]=40;
 for(int i=0;i<2;++i){uint64_t base=0x44000000ull+i*0x1000000ull,size=0x10000ull<<i;for(int k=0;k<8;++k){fdt[40+16*i+k]=(unsigned char)(base>>(56-8*k));fdt[48+16*i+k]=(unsigned char)(size>>(56-8*k));}}
 int n=tp8_memreserve(fdt,sizeof(fdt),b,s,4);fprintf(out,"memreserve %d",n);for(int i=0;i<n;++i)fprintf(out," 0x%llx+0x%llx",(unsigned long long)b[i],(unsigned long long)s[i]);fprintf(out,"\n");
 fprintf(out,"memreserve-bad %d %d\n",tp8_memreserve(fdt,30,b,s,4),tp8_memreserve(fdt,sizeof(fdt),b,s,1));
 // Cells.
 unsigned char reg[16]={0,0,0,0,0xfd,0xc0,0,0,0,0,0,0,0x02,0x40,0,0};char text[128];
 int pairs=tp8_cells(reg,16,2,2,text,sizeof(text));fprintf(out,"cells %d %s\n",pairs,text);
 pairs=tp8_cells(reg+8,8,0,2,text,sizeof(text));fprintf(out,"size %d %s\n",pairs,text);
 fprintf(out,"cells-bad %d\n",tp8_cells(reg,12,2,2,text,sizeof(text)));
 char small[12];pairs=tp8_cells(reg,16,2,2,small,sizeof(small));fprintf(out,"cells-trunc %d %s\n",pairs,small);
 // ACM line hashing with fragmented input; the last line stays unterminated.
 struct tp8_lines l;tp8_lines_init(&l);
 const char *stream=argv[5];size_t len=strlen(stream);
 for(size_t i=0;i<len;i+=3)tp8_lines_feed(&l,stream+i,len-i<3?len-i:3,report);
 fprintf(out,"lines %u pending %llu total %llu\n",l.lines,(unsigned long long)l.length,(unsigned long long)l.total);
 // UDC names: the MT6771 controller name has a dot.
 const char *udc_ok[]={"11201000.usb3","musb-hdrc.0","dummy_udc.0"},*udc_bad[]={"",".","..","a/b","bad name",".hidden"};
 for(int i=0;i<3;++i)fprintf(out,"udc-ok %s %d\n",udc_ok[i],tp8_udc_name(udc_ok[i]));
 for(int i=0;i<6;++i)fprintf(out,"udc-bad %d %d\n",i,tp8_udc_name(udc_bad[i]));
 char longname[80];memset(longname,'a',79);longname[79]=0;fprintf(out,"udc-long %d\n",tp8_udc_name(longname));
 // I2C: adapter names, hex output and the fixed read-only target table.
 const char *adapter_names[]={"i2c-0","i2c-6","i2c-12","i2c-","i2c-x","i2c-06","i2c-1a","i2c-123456","11007000.i2c","driver"};
 for(int i=0;i<10;++i)fprintf(out,"i2c-adapter %s %d\n",adapter_names[i],tp8_i2c_adapter_name(adapter_names[i]));
 unsigned char bytes[9]={0x31,0x31,0x35,0x31,0x00,0xff,0x0a,0x80,0x7f};char hex[64];
 tp8_hex_bytes(bytes,4,hex,sizeof(hex));fprintf(out,"i2c-hex %s\n",hex);
 tp8_hex_bytes(bytes,9,hex,7);fprintf(out,"i2c-hex-trunc %s\n",hex);
 for(size_t i=0;i<TP8_I2C_TARGETS;++i){const struct tp8_i2c_target *t=&tp8_i2c_targets[i];
  fprintf(out,"i2c-target %s %u %s 0x%02x %u %u %s %d\n",t->device,t->stock_bus,t->chip,t->address,t->reg_length,t->read_length,t->supply?t->supply:"-",tp8_i2c_target_valid(t));}
 struct tp8_i2c_target bad[]={{"x",0,"low",0x07,{0},1,1,NULL},{"x",0,"high",0x78,{0},1,1,NULL},{"x",0,"reg3",0x20,{0},3,1,NULL},{"x",0,"read9",0x20,{0},1,9,NULL},{"x",0,"read0",0x20,{0},1,0,NULL}};
 for(int i=0;i<5;++i)fprintf(out,"i2c-bad %s %d\n",bad[i].chip,tp8_i2c_target_valid(&bad[i]));
 // SHA-256 vectors.
 const char *vectors[]={"","abc","abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
 for(int i=0;i<3;++i){struct tp8_sha256 c;char hex[65];tp8_sha256_init(&c);tp8_sha256_update(&c,vectors[i],strlen(vectors[i]));tp8_sha256_hex(&c,hex);fprintf(out,"vector %d %s\n",i,hex);}
 fclose(out);return 0;}
'''

def main():
 checks=0
 with tempfile.TemporaryDirectory(prefix='tp8-probes-') as tmp:
  tmp=Path(tmp);disk=tmp/'disk.img';blocks=20000
  # Sizes cover sub-chunk, exact-chunk and multi-chunk partitions, and a name at the 36-character limit.
  parts=[('lk',40,40+255),('dtbo',300,300+0),('vbmeta',400,400+2),('boot',1000,1000+4095),('x'*36,6000,6000+300),('super',7000,7000+5000)]
  gpt_disk(disk,parts,blocks)
  corrupt=tmp/'corrupt.img';data=bytearray(disk.read_bytes()[:3*LBS]);data[LBS+40]^=1;corrupt.write_bytes(bytes(data)+b'\0'*((blocks-3)*LBS))
  source=tmp/'test.c';source.write_text(C_TEST);exe=tmp/'test';out=tmp/'out.txt'
  subprocess.run(['cc','-std=gnu11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I',str(HEADER.parent),str(source),'-o',str(exe)],check=True)
  stream=b'TP510-ECHO 0 abc\nsecond line\n\nunterminated'
  subprocess.run([str(exe),str(disk),str(out),str(blocks),str(corrupt),stream.decode()],check=True)
  lines=out.read_text().splitlines()
  raw=disk.read_bytes()
  assert lines[0]=='gpt count=6 why=',lines[0];checks+=1
  for name,first,last in parts:
   want=hashlib.sha256(raw[first*LBS:(last+1)*LBS]).hexdigest();size=(last-first+1)*LBS
   assert any(l==f'part {name} {parts.index((name,first,last))+1} {first} {last}' for l in lines),name
   assert any(l.startswith(f'part-hash name={name} bytes={size} sha256={want} ') for l in lines),name;checks+=1
  expired=[l for l in lines if l.startswith('part-hash name=expired ')]
  assert len(expired)==1 and 'stopped_at_deadline=1 partial prefix_bytes=0 of=4096 sha256='+hashlib.sha256(b'').hexdigest() in expired[0];checks+=1
  past=[l for l in lines if l.startswith('part-hash name=past-end ')]
  assert len(past)==1 and 'read_error=-1 partial prefix_bytes=8192 of=1048576 sha256='+hashlib.sha256(raw[-8192:]).hexdigest() in past[0],past;checks+=1
  assert 'corrupt count=-1 why=header_crc' in lines;checks+=1
  assert 'memreserve 2 0x44000000+0x10000 0x45000000+0x20000' in lines and 'memreserve-bad -1 -1' in lines;checks+=2
  assert 'cells 1 0xfdc00000+0x2400000' in lines and 'size 1 0x2400000' in lines and 'cells-bad -1' in lines;checks+=3
  assert any(l.startswith('cells-trunc 1 ') and l.endswith('...') for l in lines);checks+=1
  for i,line in enumerate([b'TP510-ECHO 0 abc',b'second line',b'']):
   assert f'acm-echo line={i+1} bytes={len(line)} sha256={hashlib.sha256(line).hexdigest()}' in lines;checks+=1
  assert f'lines 3 pending {len(b"unterminated")} total {len(stream)}' in lines;checks+=1
  assert all(f'udc-ok {n} 1' in lines for n in ['11201000.usb3','musb-hdrc.0','dummy_udc.0']);checks+=1
  assert all(f'udc-bad {i} 0' in lines for i in range(6)) and 'udc-long 0' in lines;checks+=1
  want={'i2c-0':0,'i2c-6':6,'i2c-12':12,'i2c-':-1,'i2c-x':-1,'i2c-06':-1,'i2c-1a':-1,'i2c-123456':-1,'11007000.i2c':-1,'driver':-1}
  assert all(f'i2c-adapter {k} {v}' in lines for k,v in want.items());checks+=1
  assert 'i2c-hex 31313531' in lines and 'i2c-hex-trunc 313135' in lines;checks+=1
  # Only stock-known addresses with a register pointer of at most 2 bytes and short reads.
  targets=sorted(l for l in lines if l.startswith('i2c-target '))
  assert targets==sorted(['i2c-target 11007000.i2c 0 gt1151qm 0x5d 2 4 vldo28 1','i2c-target 11007000.i2c 0 gt1151qm 0x14 2 4 vldo28 1',
   'i2c-target 1100f000.i2c 3 fs16xx 0x34 1 2 - 1','i2c-target 11005000.i2c 6 oz8806 0x2f 1 1 - 1',
   'i2c-target 11005000.i2c 6 synaptics-pad 0x20 1 6 - 1','i2c-target 11005000.i2c 6 synaptics-pad 0x2c 1 6 - 1']),targets;checks+=1
  assert all(f'i2c-bad {n} 0' in lines for n in ['low','high','reg3','read9','read0']);checks+=1
  for i,v in enumerate([b'',b'abc',b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq']):
   assert f'vector {i} {hashlib.sha256(v).hexdigest()}' in lines;checks+=1
  # The 1 GiB prefix checkpoint, through a sparse file just over 1 GiB.
  big=tmp/'big.img';gib=1<<30;big_blocks=(gib+8*LBS)//LBS+80
  gpt_disk(big,[('super',64,64+gib//LBS+7)],big_blocks,fill=False)
  subprocess.run([str(exe),str(big),str(out),str(big_blocks),str(corrupt),'x'],check=True)
  big_lines=out.read_text().splitlines();h=hashlib.sha256();prefix={}
  with big.open('rb') as f:
   f.seek(64*LBS);total=0;size=gib+8*LBS
   while total<size:
    chunk=f.read(min(1<<24,size-total));h.update(chunk);total+=len(chunk)
    if total==gib:prefix[total]=h.hexdigest()
  for k,v in prefix.items():assert any(l.startswith(f'part-hash name=super prefix_bytes={k} sha256={v} ') for l in big_lines),k
  assert any(l.startswith(f'part-hash name=super bytes={size} sha256={h.hexdigest()} ') for l in big_lines);checks+=3
  big.unlink()
  # Stock tool: commands are read-only and the log parser and comparison agree with the device lines.
  tool=runpy.run_path(str(TOOL),run_name='tool')
  rows=tool['commands']({'super':4831838208},[123])
  assert all(r.split()[0] in ('blockdev','sha256sum','head') for r in rows) and not any(w in ' '.join(rows) for w in ['dd ','of=','>','rm ','write']);checks+=1
  assert sum(r.startswith('head -c') for r in rows)==5 and 'head -c 123 /dev/block/by-name/super | sha256sum' in rows;checks+=1
  assert tool['PARTITIONS']==['lk','dtbo','vbmeta','boot','recovery','super']
  init=(ROOT/'kernel-upgrade/diagnostic-probe-v8/init.c').read_text()
  assert '{"lk", "dtbo", "vbmeta", "boot", "recovery", "super"}' in init;checks+=1
  log='\n'.join('[ 1.0] TP510-RAM-V8: '+l for l in lines+big_lines if l.startswith('part-hash'))
  device=tool['parse_log'](log)
  assert device['super']['sha256']==h.hexdigest() and device['super']['prefixes'][gib]==prefix[gib];checks+=1
  stock={'super':{'bytes':size,'sha256':h.hexdigest(),'prefixes':{str(gib):prefix[gib]}}}
  device['super']['gpt_bytes']=size
  assert tool['compare'](stock,{'super':device['super']})['super']['verdict']=='match';checks+=1
  stock['super']['prefixes'][str(gib)]='0'*64
  assert tool['compare'](stock,{'super':device['super']})['super']['verdict']=='mismatch';checks+=1
  candidate='ab'*32;rec={'recovery':{'bytes':33554432,'sha256':'cd'*32,'prefixes':{}}}
  assert tool['compare'](rec,{'recovery':{'gpt_bytes':33554432,'sha256':candidate,'prefixes':{}}},candidate)['recovery']['verdict']=='match';checks+=1
 record={'checks':checks,'sanitizers':['address','undefined'],'header_sha256':hashlib.sha256(HEADER.read_bytes()).hexdigest(),
         'tool_sha256':hashlib.sha256(TOOL.read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'device_accessed':False,'limits':['Host x86-64 build of the helpers; the ARM64 init is compiled separately and not run here',
                                         'Synthetic GPT and FDT data; the phone GPT, UFS speed and runtime reservations are only known after the trial']}
 (ROOT/'evidence/kernel-upgrade/diagnostic-probes-check-v8.json').write_text(json.dumps(record,indent=2)+'\n')
 print(f'{checks} v8 probe helper checks passed under ASan/UBSan; no device access')
if __name__=='__main__':main()

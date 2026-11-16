#!/usr/bin/env python3
"""Exercise the actual bounded query header with mocked syscalls; no device access."""
import json, subprocess, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SOURCE=r'''
#include <assert.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
static int mode, opens, queries, closes;
static int fake_lstat(const char *p,struct stat *s){assert(!__builtin_strcmp(p,"/dev/tkcoredrv"));if(mode==1){errno=ENOENT;return -1;}s->st_mode=mode==2?S_IFREG:S_IFCHR;s->st_rdev=mode==3?8:7;return 0;}
static int fake_open(const char*p,int flags,...){assert(!__builtin_strcmp(p,"/dev/tkcoredrv"));assert(flags==(O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));opens++;if(mode==4){errno=EACCES;return -1;}return 42;}
static int fake_fstat(int fd,struct stat*s){assert(fd==42);if(mode==5){errno=EIO;return -1;}s->st_mode=mode==6?S_IFREG:S_IFCHR;s->st_rdev=mode==7?8:7;return 0;}
static int fake_ioctl(int fd,unsigned long cmd,...){assert(fd==42&&cmd==0x800474b7UL);queries++;va_list args;va_start(args,cmd);unsigned *p=va_arg(args,unsigned*);va_end(args);if(mode==8||mode==10){errno=EIO;return -1;}*p=0xa55a1234;return 0;}
static int fake_close(int fd){assert(fd==42);closes++;if(mode==9||mode==10){errno=EBUSY;return -1;}return 0;}
#define lstat fake_lstat
#define open fake_open
#define fstat fake_fstat
#define ioctl fake_ioctl
#define close fake_close
#include "feature_query.h"
int main(void){struct tp_tkcore_query_result r;assert(tp_tkcore_feature_query(7,0)==-EINVAL);assert(tp_tkcore_feature_query(0,&r)==-EINVAL);assert(!opens&&!queries&&!closes);
for(mode=0;mode<=10;mode++){opens=queries=closes=0;int rc=tp_tkcore_feature_query(7,&r);assert(opens==(mode==0||mode>=4));assert(queries==(mode==0||mode>=8));assert(closes==(mode==0||mode>=5));if(mode==0){assert(!rc&&r.feature_flags==0xa55a1234&&r.stage==TP_TKCORE_QUERY_DONE);}else {assert(rc<0&&r.error_number==-rc);if(mode==10)assert(r.error_number==EIO&&r.stage==TP_TKCORE_QUERY_IOCTL);if(mode==9)assert(r.stage==TP_TKCORE_QUERY_CLOSE);}}
return 0;}
'''
with tempfile.TemporaryDirectory(prefix='tkcore-query-check-') as tmp:
    source=Path(tmp)/'test.c';exe=Path(tmp)/'test';source.write_text(SOURCE)
    subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(ROOT/'kernel-upgrade/tkcore-probe'),str(source),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
print(json.dumps({'actual_header_tested':True,'scenarios':13,'device_access':False,'sanitizers':['address','undefined']}))

#!/usr/bin/env python3
"""Check actual donor SELinux FunctionFS predicates against the upstream intent."""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
KERNEL=ROOT/'tools/kernel-source/upgrade-5.10'
def main():
 hooks=KERNEL/'security/selinux/hooks.c';text=hooks.read_text()
 special=re.search(r'static int selinux_is_genfs_special_handling\(struct super_block \*sb\)\n\{.*?\n\}',text,re.S)[0]
 mount=re.search(r'if \((!strcmp\(sb->s_type->name, "debugfs"\).*?)\)\n\s*sbsec->flags \|= SE_SBGENFS;',text,re.S)[1]
 assert 'functionfs' in special and 'functionfs' in mount
 assert 'policycap_functionfs' not in special and 'policycap_functionfs' not in mount
 prefix='''#include <stdbool.h>\n#include <string.h>\n#include <assert.h>\n#include <stdio.h>\nstruct file_system_type { const char *name; };\nstruct super_block { struct file_system_type *s_type; };\nstatic bool cgroup;\nstatic bool selinux_policycap_cgroupseclabel(void) { return cgroup; }\n'''
 program=prefix+special+'\nstatic int actual_genfs(struct super_block *sb) { return '+mount+'; }\n'+r'''
int main(void) {
 const char *names[]={"functionfs","sysfs","pstore","debugfs","tracefs","rootfs","cgroup","cgroup2","binder","bpf","securityfs","ext4"};
 unsigned int n=sizeof(names)/sizeof(names[0]),cases=0;
 for(unsigned int i=0;i<n;i++) for(int cg=0;cg<2;cg++) {
  cgroup=cg; struct file_system_type fs={names[i]};struct super_block sb={&fs};
  bool expected_special=!strcmp(names[i],"sysfs")||!strcmp(names[i],"pstore")||!strcmp(names[i],"debugfs")||!strcmp(names[i],"tracefs")||!strcmp(names[i],"rootfs")||(cg&&(!strcmp(names[i],"cgroup")||!strcmp(names[i],"cgroup2")))||!strcmp(names[i],"functionfs");
  /* Compare to this donor's baseline filesystems plus upstream cap-on FunctionFS. */
  bool expected_genfs=!strcmp(names[i],"debugfs")||!strcmp(names[i],"tracefs")||!strcmp(names[i],"binder")||!strcmp(names[i],"bpf")||!strcmp(names[i],"pstore")||!strcmp(names[i],"functionfs");
  assert(!!selinux_is_genfs_special_handling(&sb)==expected_special);
  assert(!!actual_genfs(&sb)==expected_genfs);cases+=2;
 }
 printf("%u actual-predicate cases passed\n",cases); return 0;
}
'''
 with tempfile.TemporaryDirectory(prefix='functionfs-check-') as tmp:
  p=Path(tmp);(p/'test.c').write_text(program)
  subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
  result=subprocess.run([str(p/'test')],capture_output=True,text=True,check=True)
 record={'result':result.stdout.strip(),'actual_predicate_cases':48,'hooks_sha256':hashlib.sha256(hooks.read_bytes()).hexdigest(),'functionfs_semantics_already_present':True,'functionfs_policycap_enum_present':False,'capability_off_behavior':'Donor intentionally enables FunctionFS handling unconditionally; different from upstream capability-gated behavior','new_security_code_applied':False,'policy_modified':False,'phone_accessed':False,'limits':['Source predicates with mocks, not complete inode labeling or access-control tests','Final combined policy unbuilt; enforcement unqualified','Does not implement newer netlink xperms or claim all SELinux compatibility']}
 (ROOT/'evidence/kernel-upgrade/selinux-nlmsg-review/functionfs-behavior-check.json').write_text(json.dumps(record,indent=2)+'\n');print(result.stdout,end='')
if __name__=='__main__':main()

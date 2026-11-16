#!/usr/bin/env python3
"""Offline source/configuration audit; never contacts a phone or alters shared sources."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
SHARED = pocket_paths.platform_source()


def config(path):
    values = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r'(CONFIG_\w+)=(.*)', line)
        unset = re.fullmatch(r'# (CONFIG_\w+) is not set', line)
        if match:
            values[match[1]] = match[2]
        elif unset:
            values[unset[1]] = 'n'
    return values


def main():
    output = ROOT / 'evidence/m2'
    work = ROOT / 'artifacts/m2/source-gate'
    work.mkdir(parents=True, exist_ok=True)
    source = SHARED / 'packages/modules/Connectivity/bpf/netd/BpfHandler.cpp'
    text = source.read_text()
    begin = text.index('static Status initPrograms(const char* cg2_path) {')
    end = text.index('    unique_fd cg_fd(', begin)
    prefix = text[begin:end]
    # Execute the production preflight verbatim with a deliberately small host
    # environment. This excludes program loading/attachment and target syscalls.
    harness = '''#include <cstring>
#include <iostream>
#include <string>
struct Status { std::string message; Status(const char* s):message(s){} };
static int major_version, minor_version;
static bool isAtLeastT=true, isAtLeastU=true, isAtLeastV=true, isAtLeast25Q2=true;
static bool isAtLeastKernelVersion(int a,int b) {
 return major_version>a || (major_version==a && minor_version>=b);
}
''' + prefix + '''return Status("version/cgroup preflight passed"); }
int main() {
 for (auto version : {std::pair<int,int>{4,14}, {4,19}, {5,4}}) {
  major_version=version.first; minor_version=version.second;
  std::cout << major_version << "." << minor_version << ": "
            << initPrograms("/sys/fs/cgroup").message << "\\n";
 }
}
'''
    (work / 'preflight.cc').write_text(harness)
    subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                    str(work / 'preflight.cc'), '-o', str(work / 'preflight')], check=True)
    execution = subprocess.run([str(work / 'preflight')], capture_output=True, text=True, check=True)
    (output / 'network-preflight.txt').write_text(execution.stdout)
    assert '4.14: V+ platform with kernel version < 4.19.0 is unsupported' in execution.stdout
    assert '4.19: 25Q2+ platform with kernel version < 5.4.0 is unsupported' in execution.stdout
    assert '5.4: version/cgroup preflight passed' in execution.stdout

    matrices = SHARED / 'hardware/interfaces/compatibility_matrices'
    fcm5 = matrices / 'compatibility_matrix.5.xml'
    older = ROOT / 'tools/platform-reference/lineage-21.0'
    legacy_source = older / 'android_packages_modules_Connectivity/netd/BpfHandler.cpp'
    legacy_text = legacy_source.read_text()
    legacy_begin = legacy_text.index('static Status initPrograms(const char* cg2_path) {')
    legacy_end = legacy_text.index('    unique_fd cg_fd(', legacy_begin)
    legacy_prefix = legacy_text[legacy_begin:legacy_end]
    legacy_harness = '''#include <cstring>
#include <iostream>
#include <string>
struct Status { std::string message; Status(const char* s):message(s){} };
static int sdk=34, kernel_minor=14;
namespace modules { namespace sdklevel {
bool IsAtLeastT(){return sdk>=33;} bool IsAtLeastU(){return sdk>=34;}
bool IsAtLeastV(){return sdk>=35;}
}}
namespace bpf {
bool isAtLeastKernelVersion(int a,int b,int c){
 return a<4 || (a==4 && (kernel_minor>b || (kernel_minor==b && c<=186)));
}
bool isKernel32Bit(){return false;} bool isUserspace32bit(){return false;}
}
''' + legacy_prefix + '''return Status("version/cgroup preflight passed"); }
int main(){
 std::cout<<"U/4.14: "<<initPrograms("/sys/fs/cgroup").message<<"\\n";
 sdk=36; std::cout<<"36/4.14: "<<initPrograms("/sys/fs/cgroup").message<<"\\n";
}
'''
    (work / 'legacy-preflight.cc').write_text(legacy_harness)
    subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                    str(work / 'legacy-preflight.cc'), '-o', str(work / 'legacy-preflight')], check=True)
    legacy_run = subprocess.run([str(work / 'legacy-preflight')], capture_output=True, text=True, check=True)
    assert 'U/4.14: version/cgroup preflight passed' in legacy_run.stdout
    assert '36/4.14: V+ platform with kernel version < 4.19.0 is unsupported' in legacy_run.stdout
    (output / 'lineage21-network-preflight.txt').write_text(legacy_run.stdout)
    older_fcm = older / 'android_hardware_interfaces/compatibility_matrices/compatibility_matrix.5.xml'
    required = older / 'android_kernel_configs/r/android-4.14/android-base.config'
    requirements = config(required)
    conditional = required.with_name('android-base-conditional.xml')
    conditional_xml = ET.fromstring('<requirements>' + conditional.read_text() + '</requirements>')
    configurations = {
        'installed': ROOT / 'evidence/device/20261029T000648.917229Z/root-kernel-config.txt',
        'candidate': ROOT / 'tools/kernel-build-config/some00/.config',
    }
    comparison = {}
    for name, path in configurations.items():
        current = config(path)
        differences = [{'config': key, 'required': value, 'observed': current.get(key, 'n')}
                       for key, value in requirements.items() if current.get(key, 'n') != value]
        conditional_differences, active_groups = [], 0
        for group in conditional_xml.findall('group'):
            def matches(item):
                key, value = item.findtext('key'), item.findtext('value')
                if item.find('value').attrib.get('type') != 'bool':
                    raise ValueError('Conditional evaluator only supports explicit bool values')
                return current.get(key, 'n') == value
            if all(matches(item) for item in group.findall('conditions/config')):
                active_groups += 1
                for item in group.findall('config'):
                    if not matches(item):
                        conditional_differences.append({'config': item.findtext('key'),
                                                        'required': item.findtext('value'),
                                                        'observed': current.get(item.findtext('key'), 'n')})
        comparison[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                            'differences': differences, 'active_conditional_groups': active_groups,
                            'conditional_differences': conditional_differences}
    audited_paths = [source, legacy_source, fcm5, matrices / 'Android.bp', required, conditional, older_fcm,
                     SHARED / 'system/netd/tests/kernel_test.cpp',
                     SHARED / 'packages/modules/Connectivity/bpf/loader/NetBpfLoad.cpp',
                     SHARED / 'system/linkerconfig/contents/namespace/vndk.cc']
    result = {
        'selected_branch': 'No release branch qualified; unchanged 23.2+4.14 path rejected',
        'network_gate': {'source': str(source), 'extracted_prefix_sha256': hashlib.sha256(prefix.encode()).hexdigest(),
                         'result': execution.stdout.splitlines(),
                         'scope': 'Host execution of exact production version/cgroup preflight prefix; environment version helpers stubbed; no BPF operations executed'},
        'shared_fcm5_hal_count': len(ET.parse(fcm5).getroot().findall('hal')),
        'lineage21_network_preflight': {
            'result': legacy_run.stdout.splitlines(),
            'scope': 'Exact legacy source prefix; stubbed 64-bit environment, kernel version and SDK helpers; no BPF operations'},
        'lineage21_fcm5_hal_count': len(ET.parse(older_fcm).getroot().findall('hal')),
        'legacy_android_r_4_14_base_config': {'requirements': len(requirements), 'comparison': comparison,
          'min_lts': conditional_xml.find('kernel').attrib['minlts'],
          'observed_release': '4.14.186', 'observed_meets_reference_min_lts': True,
          'limits': 'Base/boolean conditional configuration comparison only; minimum-LTS match is not current security qualification; implementation and runtime still require validation'},
        'file_identity': [{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in audited_paths],
        'device_access': 'None; phone tests paused',
    }
    (output / 'platform-compatibility.json').write_text(json.dumps(result, indent=2) + '\n')
    print(execution.stdout, end='')
    print(legacy_run.stdout, end='')
    print('FCM5 HAL definitions:', result['shared_fcm5_hal_count'], 'shared,', result['lineage21_fcm5_hal_count'], 'pinned 21 reference')
    for name, comparison in comparison.items():
        print(name, 'R/4.14 base differences:', len(comparison['differences']),
              'conditional differences:', len(comparison['conditional_differences']))


if __name__ == '__main__':
    main()

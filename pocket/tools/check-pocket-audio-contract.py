#!/usr/bin/env python3
"""Checks the first-boot vmlinux against the stock audio contract (AUDIO_PORT.md milestone 2).

Links: reads the machine driver's dai link arrays out of vmlinux (mt_soc_dai_common, then
mt_soc_btcvsd_dai, mt_soc_exthp_dai, mt_soc_extspk_dai, the order mt_soc_snd_probe copies them
in), builds each PCM id the way 5.10 does for a plain link ("<stream_name> <codec_dai>-<n>")
and compares them in order with stock's /proc/asound/pcm (evidence/audio/rea/stock-proc-asound.txt).
Link 30's codec is set at probe by mtk_spk_update_dai_link from mtk_spk_list[mtk_spk_type].
The type only changes in mtk_spk_i2c_probe, so with that driver not built (checked) it stays
MTK_SPK_NOT_SMARTPA. The compiler folds that table away, so the script reads that entry's
codec_dai_name from the source and requires the link's built-in DAI in vmlinux to be the same.

Controls: every control name in evidence/audio/kernel-contract-414.txt and every Y line of
evidence/audio/rea/ctl-in-kernel.txt must be a string in vmlinux, apart from the BTCVSD ones
(milestone 7). The speaker-path controls are listed separately. A string being there doesn't
prove the control registers; the device test does.

Minors: the card's PCM devices need a /dev/snd minor per stream when snd_card_register runs.
With CONFIG_SND_DYNAMIC_MINORS off, sound.c gives PCM device N playback minor 16+N and capture
24+N, so more than 8 devices collide and the card fails with -EBUSY. The check reads the .config
next to vmlinux, counts streams from stock's /proc/asound/pcm and checks they fit the way
snd_find_free_minor hands them out.

Host only: no build and no phone access. Pointers in vmlinux data are 0 until relocated
(CONFIG_RELOCATABLE, --no-apply-dynamic-relocs), so they're read from .rela.dyn.
"""
import pocket_paths
import argparse, os, re, struct, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
VMLINUX = BULK / 'kernel-firstboot-5.10/vmlinux'
STOCK_PCM = ROOT / 'evidence/audio/rea/stock-proc-asound.txt'
CONTRACT = ROOT / 'evidence/audio/kernel-contract-414.txt'
HAL_CTL = ROOT / 'evidence/audio/rea/ctl-in-kernel.txt'
LINK_ARRAYS = ['mt_soc_dai_common', 'mt_soc_btcvsd_dai', 'mt_soc_exthp_dai', 'mt_soc_extspk_dai']
SPEAKER_LINK = 30
SPEAKER_AMP_C = ROOT / 'tools/kernel-source/upgrade-5.10/sound/soc/mediatek/common_int/mtk-soc-speaker-amp.c'
# 5.10 struct snd_soc_dai_link (include/sound/soc.h): name 0, stream_name 8, cpus 16, codecs 32.
LINK_NAME, LINK_STREAM, LINK_CODECS = 0, 8, 32
COMPONENT_DAI_NAME = 16  # struct snd_soc_dai_link_component: name, of_node, dai_name
SPEAKER_CONTROLS = [
    'Speaker_Amp_Switch', 'Ext_Speaker_Amp_Switch', 'Headset_Speaker_Amp_Switch', 'Receiver_Speaker_Switch',
    'Lineout_PGAL_GAIN', 'Lineout_PGAR_GAIN', 'Audio_Amp_L_Switch', 'Audio_Amp_R_Switch', 'Handset_PGA_GAIN',
    'Headset_PGAL_GAIN', 'Headset_PGAR_GAIN', 'Audio_i2s0_SideGen_Switch', 'Audio_i2s0_hd_Switch',
    'Audio_I2S0dl1_hd_Switch', 'Audio_ExtCodec_EchoRef_Switch', 'Audio_always_hd_Switch', 'Audio_Mode_Switch',
    'MTK_SPK_TYPE_GET', 'Audio_I2S1_Setting', 'deep_buffer_dl_hd_Switch', 'fast_dl_hd_Switch',
    'Audio_DL2_DataTransfer', 'Audio IRQ1 CNT', 'Audio_Assign_DRAM']


class Elf:
    def __init__(self, data):
        self.d = data
        assert data[:4] == b'\x7fELF' and data[4] == 2 and data[5] == 1, 'not a little-endian ELF64'
        shoff, = struct.unpack_from('<Q', data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
        self.sections = []
        for i in range(shnum):
            name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
                '<IIQQQQIIQQ', data, shoff + i * shentsize)
            self.sections.append(dict(name=name, type=typ, addr=addr, off=off, size=size, link=link, entsize=entsize))
        strtab = self.sections[shstrndx]
        for s in self.sections:
            s['name'] = self.cstr_at(strtab['off'] + s['name'])
        self.relocs = {}
        for s in self.sections:
            if s['type'] == 4:  # SHT_RELA
                for o in range(s['off'], s['off'] + s['size'], 24):
                    r_off, r_info, r_add = struct.unpack_from('<QQq', data, o)
                    if r_info & 0xffffffff == 1027:  # R_AARCH64_RELATIVE
                        self.relocs[r_off] = r_add & (2 ** 64 - 1)

    def cstr_at(self, off):
        return self.d[off:self.d.index(b'\0', off)].decode()

    def symbols(self):
        out = {}
        for s in self.sections:
            if s['type'] != 2:  # SHT_SYMTAB
                continue
            names = self.sections[s['link']]
            for o in range(s['off'], s['off'] + s['size'], 24):
                st_name, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', self.d, o)
                if st_name:
                    out.setdefault(self.cstr_at(names['off'] + st_name), (value, size))
        return out

    def offset(self, addr):
        for s in self.sections:
            if s['type'] != 8 and s['addr'] <= addr < s['addr'] + s['size']:  # not NOBITS
                return s['off'] + addr - s['addr']
        raise KeyError(hex(addr))

    def pointer(self, addr):
        if addr in self.relocs:
            return self.relocs[addr]
        return struct.unpack_from('<Q', self.d, self.offset(addr))[0]

    def string(self, addr):
        p = self.pointer(addr)
        return self.cstr_at(self.offset(p)) if p else None


def links(elf, syms):
    # mt_soc_btcvsd_dai holds one link, so its size is sizeof(struct snd_soc_dai_link)
    stride = syms['mt_soc_btcvsd_dai'][1]
    result = []
    for array in LINK_ARRAYS:
        base, size = syms[array]
        assert size % stride == 0, (array, size, stride)
        for i in range(size // stride):
            at = base + i * stride
            codecs = elf.pointer(at + LINK_CODECS)
            result.append(dict(array=array, name=elf.string(at + LINK_NAME), stream=elf.string(at + LINK_STREAM),
                               codec_dai=elf.string(codecs + COMPONENT_DAI_NAME)))
    return result


def minors(config_path, stock_text, devices):
    # include/sound/minors.h and sound/core/sound.c snd_find_free_minor, card 0 only
    config = dict(re.findall(r'^CONFIG_(\w+)=(.*)$', config_path.read_text(), re.M))
    if config.get('SND') != 'y':
        return [f'{config_path}: CONFIG_SND=y not found, not a first-boot .config']
    dynamic = config.get('SND_DYNAMIC_MINORS') == 'y'
    streams = sum(len(re.findall(r': (?:playback|capture) \d+', l))
                  for l in stock_text.splitlines() if l.startswith('00-'))
    if dynamic:
        # all 256 minors except each slot's control minor, the sequencer (1) and the timer (33)
        free = 256 - 256 // 32 - 2
        print(f'minors: dynamic, {streams} PCM streams, {free} free minors')
        if streams > free:
            return [f'{streams} PCM streams do not fit {free} dynamic minors']
        return []
    print(f'minors: static, room for 8 PCM devices per card, {devices} links')
    if devices > 8:
        return [f'CONFIG_SND_DYNAMIC_MINORS is off: PCM device 8 playback takes device 0 capture\'s minor, '
                f'snd_card_register fails -EBUSY ({devices} devices, {streams} streams)']
    return []


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--vmlinux', type=Path, default=VMLINUX)
    p.add_argument('--config', type=Path, help='kernel .config (default: next to vmlinux)')
    a = p.parse_args()
    data = a.vmlinux.read_bytes()
    elf = Elf(data)
    syms = elf.symbols()
    fails = []

    stock = re.findall(r'^00-(\d\d): (.*?) :  :', STOCK_PCM.read_text(), re.M)
    built = links(elf, syms)
    if 'mtk_spk_i2c_probe' in syms:
        fails.append('mtk_spk_i2c_probe is built, so link 30 can change at runtime')
    speaker_dai = re.search(r'\[MTK_SPK_NOT_SMARTPA\] = \{\s*\.codec_dai_name = "([^"]+)"',
                            SPEAKER_AMP_C.read_text()).group(1)
    print(f'link {SPEAKER_LINK} codec DAI after mtk_spk_update_dai_link: {speaker_dai}')
    if len(built) > SPEAKER_LINK and built[SPEAKER_LINK]['codec_dai'] != speaker_dai:
        fails.append(f"link {SPEAKER_LINK} built with {built[SPEAKER_LINK]['codec_dai']}, probe sets {speaker_dai}")
    print(f'{len(built)} links in vmlinux, {len(stock)} PCMs on stock')
    if len(built) != len(stock):
        fails.append(f'{len(built)} links, stock has {len(stock)}')
    for n, link in enumerate(built):
        dai = speaker_dai if n == SPEAKER_LINK else link['codec_dai']
        pcm_id = f"{link['stream']} {dai}-{n}"
        want = stock[n][1] if n < len(stock) else None
        ok = pcm_id == want
        print(f"{'ok  ' if ok else 'DIFF'} {n:02d} {pcm_id}" + ('' if ok else f'  (stock: {want})'))
        if not ok:
            fails.append(f'link {n}: {pcm_id} != {want}')

    fails += minors(a.config or a.vmlinux.parent / '.config', STOCK_PCM.read_text(), len(built))

    strings = set(re.findall(rb'[\x20-\x7e]{3,}(?=\0)', data))
    contract = [l.split('\t')[2] for l in CONTRACT.read_text().splitlines()
                if l.startswith('sound/') and l.count('\t') == 2]
    hal = [l[2:] for l in HAL_CTL.read_text().splitlines() if l.startswith('Y ')]
    deferred = lambda n: n.startswith('BTCVSD')
    for label, names in [('kernel-contract-414.txt', contract), ('ctl-in-kernel.txt Y', hal),
                         ('speaker path', SPEAKER_CONTROLS)]:
        missing = [n for n in names if n.encode() not in strings]
        later = [n for n in missing if deferred(n)]
        bad = [n for n in missing if not deferred(n)]
        print(f'{label}: {len(names) - len(missing)} of {len(names)} present'
              + (f', {len(later)} BTCVSD for milestone 7' if later else ''))
        for n in bad:
            print(f'  missing: {n}')
            fails.append(f'{label}: {n}')

    if fails:
        print('FAIL: ' + '; '.join(fails))
        return 1
    print('PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())

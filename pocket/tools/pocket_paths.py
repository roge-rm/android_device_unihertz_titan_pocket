"""Where the private inputs live on this machine.

Set them in configs/local-paths.json (git-ignored), for example:
  {"build_root": "/path/to/build-root", "platform_source": "/path/to/lineage-source",
   "private_vendor": "/path/to/stock-vendor-dir", "private_vendor_overlay": "/path/to/overlay-dir",
   "release_keys": "/path/to/release-key-folder"}
POCKET_PATHS names another config file. POCKET_BUILD_ROOT and POCKET_PLATFORM_SOURCE override their keys.
There is no default: the path is only looked up when a tool uses it, and then it stops with a message
if the key is missing. --help and checks that use only the repo work without the file.
The Android SDK is ANDROID_SDK_ROOT, else Android/Sdk in the home folder.
"""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = Path(os.environ.get('POCKET_PATHS') or ROOT / 'configs/local-paths.json')
ENV = {'build_root': 'POCKET_BUILD_ROOT', 'platform_source': 'POCKET_PLATFORM_SOURCE'}
NDK = 'ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'

# The device tree: device/unihertz/titan_pocket here, or the folder above pocket/ in the exported device repo.
_PRIVATE_LAYOUT = ROOT / 'device/unihertz/titan_pocket'
DEVICE_TREE = _PRIVATE_LAYOUT if _PRIVATE_LAYOUT.is_dir() else ROOT.parent
EXPORTED_LAYOUT = not _PRIVATE_LAYOUT.is_dir()
INPUT_PACKAGE = ROOT / 'packages/PocketInput' if (ROOT / 'packages/PocketInput').is_dir() else DEVICE_TREE / 'PocketInput'

# Text that must not appear in a published file, built from pieces so this file passes its own scan.
PRIVATE_MARKERS = ('/s' + 'rv/', '/ho' + 'me/', 'private' + '-vendor', 'private' + '-inputs')


def get(key):
    if key in ENV and os.environ.get(ENV[key]):
        return os.environ[ENV[key]]
    if CONFIG.is_file():
        value = json.loads(CONFIG.read_text()).get(key)
        if value:
            return value
    hint = f' (or set {ENV[key]})' if key in ENV else ''
    raise SystemExit(f'This tool needs the private input "{key}". Set it in {CONFIG}{hint}.')


class LazyPath:
    """A path that is looked up in the config when first used, not when the tool starts."""

    def __init__(self, resolve):
        self._resolve = resolve
        self._path = None

    def path(self):
        if self._path is None:
            self._path = Path(self._resolve())
        return self._path

    def __fspath__(self):
        return str(self.path())

    __str__ = __fspath__

    def __repr__(self):
        return 'LazyPath()'

    def __truediv__(self, other):
        return LazyPath(lambda: self.path() / other)

    def __eq__(self, other):
        return self.path() == other

    def __hash__(self):
        return hash(self.path())

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return getattr(self.path(), name)


def _lazy(key):
    return LazyPath(lambda: get(key))


def build_root():
    return _lazy('build_root')


def platform_root():
    return _lazy('platform_root')


def platform_source():
    return _lazy('platform_source')


def private_vendor():
    return _lazy('private_vendor')


def private_vendor_overlay():
    return _lazy('private_vendor_overlay')


def release_keys():
    return _lazy('release_keys')


def android_sdk():
    return Path(os.environ.get('ANDROID_SDK_ROOT') or Path.home() / 'Android/Sdk')


def ndk_bin():
    return android_sdk() / NDK


def device_serial():
    return get('device_serial')


def lab_ssh(host=None):
    """ssh argv for the lab host: key and user@host come from the config."""
    target = get('lab_user') + '@' + (host or get('lab_host'))
    alias = json.loads(CONFIG.read_text()).get('lab_host_key_alias') if CONFIG.is_file() else None
    return (['ssh', '-i', get('lab_ssh_key'), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes']
            + (['-o', 'HostKeyAlias=' + alias] if alias else []) + ['-o', 'ConnectTimeout=10', target])

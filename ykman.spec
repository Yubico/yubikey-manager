# -*- mode: python -*-

# This is a spec file used by PyInstaller to build a single executable for ykman.
# See: https://pyinstaller.readthedocs.io/en/stable/spec-files.html

# This recipe allows PyInstaller to understand the entrypoint.
# See: https://github.com/pyinstaller/pyinstaller/wiki/Recipe-Setuptools-Entry-Point
def Entrypoint(dist, group, name, **kwargs):
    import pkg_resources

    # get toplevel packages of distribution from metadata
    def get_toplevel(dist):
        distribution = pkg_resources.get_distribution(dist)
        if distribution.has_metadata('top_level.txt'):
            return list(distribution.get_metadata('top_level.txt').split())
        else:
            return []

    kwargs.setdefault('hiddenimports', [])
    packages = []
    for distribution in kwargs['hiddenimports']:
        packages += get_toplevel(distribution)

    kwargs.setdefault('pathex', [])
    # get the entry point
    ep = pkg_resources.get_entry_info(dist, group, name)
    # insert path of the egg at the verify front of the search path
    kwargs['pathex'] = [ep.dist.location] + kwargs['pathex']
    # script name must not be a valid module name to avoid name clashes on import
    script_path = os.path.join(workpath, name + '-script.py')
    print("creating script for entry point", dist, group, name)
    with open(script_path, 'w') as fh:
        print("import", ep.module_name, file=fh)
        print("%s.%s()" % (ep.module_name, '.'.join(ep.attrs)), file=fh)
        for package in packages:
            print("import", package, file=fh)

    return Analysis(
        [script_path] + kwargs.get('scripts', []),
        **kwargs
    )


block_cipher = None

# Extra .dlls and .dylibs are added to the executable.
macos_dylibs = [ 
    ('libjson-c.4.dylib', '.' ),
    ('libjson-c.dylib', '.'),
    ('libykpers-1.1.dylib', '.'),
    ('libykpers-1.dylib', '.'),
    ('libyubikey.0.dylib', '.'),
    ('libyubikey.dylib', '.'),
]

win_dlls = [
    ('libjson-c-2.dll', '.' ),
    ('libusb-1.0.dll', '.' ),
    ('libykpers-1-1.dll', '.' ),
    ('libyubikey-0.dll', '.' ),
    ('libjson-0.dll', '.' ),
]

# Extra data files to be added to executable.
data_files = [('ykman/VERSION', 'ykman/')]

import sys
import platform

universal_crt = ['']
binary_files = None

# On Windows we bundle the Universal CRT, see:
# https://github.com/pyinstaller/pyinstaller/blob/develop/doc/usage.rst#windows

# We also do a workaround for pyscard, see:
# https://stackoverflow.com/questions/49718551/pyinstaller-fails-with-pyscard-on-windows
if sys.platform == 'win32':
    binary_files = win_dlls
    pyscard_patch = None
    if platform.architecture()[0] == '32bit':
        pyscard_patch = 'C:\\Python36\\lib\\site-packages\\smartcard\\scard\\_scard.cp36-win32.pyd'
        universal_crt = ['C:\\Program Files (x86)\\Windows Kits\\10\\Redist\\ucrt\\DLLs\\x86']
    if platform.architecture()[0] == '64bit':
        pyscard_patch = 'C:\\Python36-x64\\lib\\site-packages\\smartcard\\scard\\_scard.cp36-win_amd64.pyd'
        universal_crt = ['C:\\Program Files (x86)\\Windows Kits\\10\\Redist\\ucrt\\DLLs\\x64']
    data_files.append((pyscard_patch , '.\\smartcard\\scard\\'))

if sys.platform == 'darwin':
    binary_files = macos_dylibs

a = Entrypoint(
    'yubikey-manager',
    'console_scripts',
    'ykman',
    datas=data_files,
    pathex=universal_crt,
    binaries=binary_files)

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='ykman',
          debug=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True)

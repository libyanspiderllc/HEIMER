# -*- mode: python ; coding: utf-8 -*-
import subprocess
import sys

# Check GLIBC version compatibility
try:
    glibc_version = subprocess.check_output(['ldd', '--version']).decode().split('\n')[0].split()[-1]
    print(f"Building with GLIBC version: {glibc_version}")
except:
    print("Warning: Could not determine GLIBC version")

block_cipher = None

# Try to bundle system libraries to reduce runtime dependencies
a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[('/lib64/libz.so.1', '.')],  # Include zlib
    datas=[('test_data/netstat_sample.txt', 'test_data')],  # Include test data
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='heimer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

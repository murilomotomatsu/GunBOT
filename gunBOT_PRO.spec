# -*- mode: python ; coding: utf-8 -*-
# GunBot PRO - PyInstaller Spec File

import os

# Collect all module files
block_cipher = None

a = Analysis(
    ['gunBot.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('ico.ico', '.'),
        ('config.py', '.'),
        ('core', 'core'),
        ('automation', 'automation'),
        ('engine', 'engine'),
        ('ui', 'ui'),
    ],
    hiddenimports=[
        'config',
        'core',
        'core.utils',
        'core.license',
        'core.updater',
        'automation',
        'automation.window',
        'automation.input',
        'automation.locate',
        'engine',
        'engine.runner',
        'ui',
        'ui.app',
        'PIL',
        'PIL.Image',
        'PIL.ImageTk',
        'PIL.ImageGrab',
        'cv2',
        'numpy',
        'win32gui',
        'win32ui',
        'win32con',
        'win32api',
        'pynput',
        'pynput.mouse',
        'pynput.keyboard',
        'requests',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='gunBOT_PRO',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='ico.ico',
)

# ghost_tracker.spec
# Build command: pyinstaller ghost_tracker.spec

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['ghost_tracker/cli.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('README.md', '.'),
        ('LICENSE', '.'),
    ],
    hiddenimports=[
        'psutil',
        'psutil._psmacosx',
        'rich',
        'rich.console',
        'rich.layout',
        'rich.live',
        'rich.panel',
        'rich.table',
        'rich.text',
        'rich.columns',
        'rich.align',
        'ghost_tracker.core',
        'ghost_tracker.dashboard',
        'ghost_tracker.cli',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zlib_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ghost-tracker',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # Terminal app — needs console
    disable_windowed_traceback=False,
    target_arch=None,      # Universal (Intel + Apple Silicon)
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

# macOS .app bundle
app = BUNDLE(
    exe,
    name='Ghost Tracker.app',
    icon=None,
    bundle_identifier='com.ghosttracker.app',
    info_plist={
        'NSPrincipalClass': 'NSApplication',
        'NSAppleScriptEnabled': False,
        'CFBundleName': 'Ghost Tracker',
        'CFBundleDisplayName': 'Ghost Tracker',
        'CFBundleVersion': '1.0.0',
        'CFBundleShortVersionString': '1.0.0',
        'NSHumanReadableCopyright': 'MIT License',
        'LSUIElement': False,
        'NSRequiresAquaSystemAppearance': False,
    },
)

# ghost_tracker.spec
# Build: pyinstaller ghost_tracker.spec

block_cipher = None

a = Analysis(
    ['ghost_tracker/cli.py'],
    pathex=['.'],
    binaries=[],
    datas=[('README.md', '.'), ('LICENSE', '.')],
    hiddenimports=[
        'psutil',
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
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy'],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ghost-tracker',
    debug=False,
    strip=False,
    upx=True,
    console=True,
    target_arch=None,
)

app = BUNDLE(
    exe,
    name='Ghost Tracker.app',
    bundle_identifier='com.ghosttracker.app',
    info_plist={
        'CFBundleName': 'Ghost Tracker',
        'CFBundleDisplayName': 'Ghost Tracker',
        'CFBundleVersion': '1.0.0',
        'CFBundleShortVersionString': '1.0.0',
        'NSHumanReadableCopyright': 'MIT License',
    },
)

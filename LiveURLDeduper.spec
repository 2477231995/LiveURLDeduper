# -*- mode: python ; coding: utf-8 -*-
# 用 LiveURLDeduper.spec 打包：pyinstaller LiveURLDeduper.spec
# 或者直接跑 build_exe.bat（会检查 / 转换图标后调这个 spec）

import os

block_cipher = None

# --------------------------------------------------------------------------- #
# 图标：build_exe.bat 通过 LIVEURLDEDUPER_ICON 传进来；直接跑 spec 就退回 myicon.ico
# --------------------------------------------------------------------------- #
_icon_env = os.environ.get("LIVEURLDEDUPER_ICON") or os.path.join(SPECPATH, "myicon.ico")
if os.path.isfile(_icon_env):
    icon_file = os.path.abspath(_icon_env)
    print(f"[LiveURLDeduper.spec] icon: {icon_file}")
else:
    icon_file = None
    print(f"[LiveURLDeduper.spec] WARN icon not found: {_icon_env} -> building without icon")

# --------------------------------------------------------------------------- #
# tkinterdnd2 是可选的（装了才能把文件拖进窗口），没装就跳过，不要影响打包
# --------------------------------------------------------------------------- #
try:
    from PyInstaller.utils.hooks import collect_data_files

    import tkinterdnd2  # noqa: F401

    _hiddenimports = ['socks', 'sockshandler', 'tkinterdnd2']
    _datas = collect_data_files('tkinterdnd2')
except Exception:
    _hiddenimports = ['socks', 'sockshandler']
    _datas = []

a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=_datas,
    hiddenimports=_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # 这些是 urllib3.contrib.pyopenssl 的 hook 顺手拖进来的（运行时压根没 import）：
    # cryptography 的 rust pyd 就 3.5MB，加 libcrypto/libssl/bcrypt 一共省 ~6.5MB
    excludes=[
        # 测试/构建期的东西
        'pytest', 'unittest', 'test', 'doctest', 'pdb', 'pydoc', 'pydoc_data',
        'setuptools', 'pkg_resources', 'pip', 'distutils', 'lib2to3', 'ensurepip',
        # urllib3.contrib.pyopenssl 的 hook 顺手拖进来的，运行时压根没 import
        'cryptography', 'bcrypt', 'cffi', '_cffi_backend', 'OpenSSL',
        'paramiko', 'nacl', 'Crypto',
        # 用不到的标准库（GUI 工具只做 HTTP 探测 + 写文件）
        'xml', 'xmlrpc', 'pyexpat', '_decimal', 'decimal', 'sqlite3', 'dbm',
        'asyncio', 'multiprocessing', 'socketserver', 'http.server', 'cgi',
        'webbrowser', 'curses', 'venv', 'zoneinfo', 'turtle', 'idlelib',
        'tkinter.test', 'email.mime',
    ],
    # 去掉 docstring/断言，PYZ 能再小一截；本项目不靠 __doc__ 干活
    optimize=2,
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
    name='LiveURLDeduper',
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
    icon=icon_file,
)

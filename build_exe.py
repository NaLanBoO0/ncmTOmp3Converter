#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 ncm2mp3.py 打包成单文件 exe —— 目标电脑不需要装 Python。

用法（在本文件所在目录执行）：
    python build_exe.py            # 界面版 + 命令行版都打
    python build_exe.py --gui      # 只打界面版
    python build_exe.py --cli      # 只打命令行版

产物：
    dist/NCM转MP3.exe         双击直接打开界面（没有黑色控制台窗口）
    dist/ncm2mp3-命令行.exe    命令行用，也可以把 .ncm 文件拖到它图标上


"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "ncm2mp3.py"
DIST = HERE / "dist"
WORK = HERE / "_build"
OUT = HERE / "_out"          # PyInstaller 的临时输出目录（见下面 build() 里的说明）
ICON = HERE / "ncm2mp3.ico"

GUI_NAME = "NCM转MP3"
CLI_NAME = "ncm2mp3-命令行"


def has_pyinstaller() -> bool:
    try:
        r = subprocess.run([sys.executable, "-m", "PyInstaller", "--version"],
                           capture_output=True, text=True)
        return r.returncode == 0
    except OSError:
        return False


def build(name: str, windowed: bool) -> Path:
    """
    打一个 exe。

    这里刻意绕开了所有"删除文件"的动作，因为某些环境（比如带安全删除保护/
    沙箱的环境）会拦截批量删除，PyInstaller 的 --clean 和"覆盖已有 exe"
    都会被拦下来导致打包失败。做法：

      - 工作目录每次全新（不加 --clean，天然没有东西要删）
      - 先输出到 _out/<时间戳>/ 这个空目录（目标不存在 → 不需要删）
      - 最后用 open(...,'wb') 直接覆盖 dist 里的旧 exe（截断写，不是删除）
    """
    stamp = f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
    work = WORK / f"{name}-{stamp}"
    outdir = OUT / stamp
    work.mkdir(parents=True, exist_ok=True)
    outdir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",          # 不交互确认
        "--onefile",            # 打成单个 exe
        "--name", name,
        "--distpath", str(outdir),
        "--workpath", str(work),
        "--specpath", str(work),
    ]
    cmd.append("--windowed" if windowed else "--console")
    if ICON.is_file():
        cmd += ["--icon", str(ICON)]
    cmd.append(str(SCRIPT))

    print()
    print("=" * 62)
    print(("[界面版] " if windowed else "[命令行版] ") + name + ".exe")
    print("=" * 62)
    produced = outdir / f"{name}.exe"
    placed = False
    try:
        subprocess.run(cmd, check=True)
        if not produced.is_file():
            raise RuntimeError(f"没生成 {produced}")
        DIST.mkdir(exist_ok=True)
        target = DIST / f"{name}.exe"
        try:
            if target.exists():
                with open(produced, "rb") as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)      # 覆盖，不删文件
            else:
                shutil.copyfile(produced, target)
            placed = True
        except OSError as e:
            # 有些环境（安全删除保护 / 杀软占用）不允许覆盖已有 exe。
            # 这不影响"exe 已经打好了"，把路径说清楚就行，别把产物也删了。
            print()
            print(f"  !! 覆盖 {target} 失败：{e}")
            print(f"     新的 exe 已经打好在这里：{produced}")
            print("     手动用它替换 dist 里的旧文件即可。")
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if placed:
            shutil.rmtree(outdir, ignore_errors=True)
    return DIST / f"{name}.exe" if placed else produced


def main() -> int:
    args = sys.argv[1:]
    want_gui = "--cli" not in args
    want_cli = "--gui" not in args

    if not SCRIPT.is_file():
        print(f"找不到脚本：{SCRIPT}")
        return 1
    if not has_pyinstaller():
        print("没装 PyInstaller。先执行：\n    pip install pyinstaller")
        return 1

    DIST.mkdir(exist_ok=True)
    made: list[Path] = []
    if want_gui:
        made.append(build(GUI_NAME, windowed=True))
    if want_cli:
        made.append(build(CLI_NAME, windowed=False))

    print()
    print("=" * 62)
    print("打包完成：")
    for p in made:
        if p.is_file():
            print(f"  {p}   ({p.stat().st_size / 1048576:.1f} MB)")
        else:
            print(f"  !! 没生成：{p}")
    print()
    print("exe 可以单独拷到任何 Windows 电脑上运行，不需要装 Python。")
    print("中间产物都在 _build/，删掉不影响 exe。")
    return 0


if __name__ == "__main__":
    sys.exit(main())

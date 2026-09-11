#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ncm2mp3 —— 网易云音乐 .ncm 缓存文件解密 / 转码工具
Na1aB做的小工具
功能
    1. 解析 .ncm 文件头，取出内嵌的封面、歌曲元数据（歌名/歌手/专辑）
    2. 还原被加密的音频流，自动识别真实格式（通常是 mp3 或 flac）
    3. 按 "歌名 - 歌手" 命名输出，可选导出封面
    4. 可选：非 mp3 的源（如 flac）用 ffmpeg 转成 mp3


合规提示
    本工具只解决"格式转换/解封装"，不绕过任何付费或会员校验。
    请仅用于转换你自己已合法获取的音频文件，不要用于传播或商业分发。

用法
    python ncm2mp3.py                        # 打开本地网页控制台（拖拽转换，推荐）
    python ncm2mp3.py <文件或目录> [-o 输出目录] [-j 进程数] [--to-mp3] [--cover]

    例：
    python ncm2mp3.py                          # 网页控制台，浏览器里拖文件进去
    python ncm2mp3.py D:\\Music\\ncm            # 递归转换整个目录，输出到同目录
    python ncm2mp3.py D:\\a.ncm -o D:\\out -j 4  # 指定输出目录，4 进程
    python ncm2mp3.py --here                    # 命令行模式转换当前目录
    python ncm2mp3.py D:\\Music\\ncm --to-mp3    # flac 源也强制转成 mp3（需要 ffmpeg）

图形界面说明
    不需要 tkinter，也不需要装任何第三方包。界面是一个本地网页，启动时会以
    「应用窗口」模式打开（Edge / Chrome 的 --app 参数）—— 没有地址栏、没有标签页，
    看起来就和一个普通桌面程序一样。找不到 Edge/Chrome 时自动退回默认浏览器，
    用 --no-app 可以强制用普通标签页打开。
    可以把 .ncm 文件或整个文件夹直接拖进去，也支持填本地目录路径批量转换。
    服务只监听 127.0.0.1 且带一次性访问令牌，文件不会离开这台电脑。
    关掉界面窗口程序就会退出（正在转换的任务会先跑完）。

打包成 exe
    python build_exe.py            # 生成 dist/NCM转MP3.exe，单文件、免安装
    打包后的 exe 双击即打开界面，不依赖目标电脑装 Python。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

# ---------------------------------------------------------------------------
# 打包运行环境适配
# ---------------------------------------------------------------------------

IS_FROZEN = getattr(sys, "frozen", False)   # 是否运行在 PyInstaller 打出的 exe 里


def _ensure_std_streams() -> None:
    """
    打包成 --windowed（无控制台）的 exe 后，sys.stdout / sys.stderr 是 None，
    任何 print 都会抛 AttributeError。这里给它们兜个空流，保证不炸。
    """
    for name in ("stdout", "stderr"):
        if getattr(sys, name, None) is None:
            try:
                setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
            except OSError:
                pass


def _popup(title: str, text: str) -> None:
    """无控制台环境下用系统弹窗把错误告诉用户（纯 ctypes，无第三方依赖）。"""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, text, title, 0x10)
    except Exception:
        print(f"{title}: {text}")


def default_output_dir() -> Path:
    """界面里"导出到"的默认目录：用户「音乐」文件夹下的 NCM输出。"""
    for cand in (Path.home() / "Music", Path.home() / "音乐", Path.home()):
        if cand.is_dir():
            return cand / "NCM输出"
    return Path.cwd() / "NCM输出"


def html_attr(s: object) -> str:
    """把字符串安全地塞进 HTML 属性值里。"""
    return (str(s).replace("&", "&amp;").replace('"', "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;"))

# ---------------------------------------------------------------------------
# 常量：NCM 格式里写死的两个密钥
# ---------------------------------------------------------------------------

NCM_MAGIC = b"CTENFDAM"

# 用于解密"核心密钥块"的 AES-128 密钥（ASCII: hzHRAmso5kInbaxW）
CORE_KEY = bytes.fromhex("687A4852416D736F356B496E62617857")
# 用于解密元数据 JSON 的 AES-128 密钥（ASCII: #14ljk_!\]&0U<'( ）
META_KEY = bytes.fromhex("2331346C6A6B5F215C5D2630553C2728")

# 核心密钥块 / 元数据块在 AES 解密前，要先逐字节异或这两个常量
KEY_XOR = 0x64
META_XOR = 0x63

# 核心密钥块解密后，开头固定有 17 字节的标识串，需要丢掉
KEY_PREFIX_LEN = 17      # len("neteasecloudmusic")
# 元数据块 base64 解码后，开头固定有 6 字节 "music:"
META_PREFIX_LEN = 6
# 元数据块 base64 解码前，开头有 22 字节的标识串 "163 key(Don't modify):"
META_TAG_LEN = 22


# ---------------------------------------------------------------------------
# 纯 Python AES-128-ECB 解密（只实现解密方向，够用）
# ---------------------------------------------------------------------------

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

_INV_SBOX = bytes.fromhex(
    "52096ad53036a538bf40a39e81f3d7fb"
    "7ce339829b2fff87348e4344c4dee9cb"
    "547b9432a6c2233dee4c950b42fac34e"
    "082ea16628d924b2765ba2496d8bd125"
    "72f8f66486689816d4a45ccc5d65b692"
    "6c704850fdedb9da5e154657a78d9d84"
    "90d8ab008cbcd30af7e45805b8b34506"
    "d02c1e8fca3f0f02c1afbd0301138a6b"
    "3a9111414f67dcea97f2cfcef0b4e673"
    "96ac7422e7ad3585e2f937e81c75df6e"
    "47f11a711d29c5896fb7620eaa18be1b"
    "fc563e4bc6d279209adbc0fe78cd5af4"
    "1fdda8338807c731b11210592780ec5f"
    "60517fa919b54a0d2de57a9f93c99cef"
    "a0e03b4dae2af5b0c8ebbb3c83539961"
    "172b047eba77d626e169146355210c7d"
)


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    """GF(2^8) 上的乘法，模为 AES 的不可约多项式 0x11B。"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


def _expand_key(key: bytes) -> list[bytes]:
    """AES-128 密钥扩展：1 个 16 字节主密钥 -> 11 组轮密钥。"""
    if len(key) != 16:
        raise ValueError("AES-128 需要 16 字节密钥")
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                    # RotWord
            t = [_SBOX[b] for b in t]            # SubWord
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes(b for row in w[i * 4:(i + 1) * 4] for b in row) for i in range(11)]


def _inv_shift_rows(s: list[int]) -> None:
    """逆行移位（state 按列优先存放：s[r + 4c]）。原地修改。"""
    s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]


def _inv_mix_columns(s: list[int]) -> None:
    """逆列混合。原地修改。"""
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
        s[i] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
        s[i + 1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
        s[i + 2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
        s[i + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)


def _decrypt_block(block: bytes, rk: list[bytes]) -> bytes:
    s = list(block)
    s = [s[i] ^ rk[10][i] for i in range(16)]
    for rnd in range(9, 0, -1):
        _inv_shift_rows(s)
        s = [_INV_SBOX[b] for b in s]
        s = [s[i] ^ rk[rnd][i] for i in range(16)]
        _inv_mix_columns(s)
    _inv_shift_rows(s)
    s = [_INV_SBOX[b] for b in s]
    s = [s[i] ^ rk[0][i] for i in range(16)]
    return bytes(s)


def aes128_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-ECB 解密。data 长度必须是 16 的倍数（不足则补零）。"""
    if len(data) % 16:
        data = data + b"\x00" * (16 - len(data) % 16)
    rk = _expand_key(key)
    out = bytearray()
    for off in range(0, len(data), 16):
        out += _decrypt_block(data[off:off + 16], rk)
    return bytes(out)


# ---------------------------------------------------------------------------
# NCM 音频流的解密：一个 RC4 变种流密码
# ---------------------------------------------------------------------------

def build_key_box(key: bytes) -> bytes:
    """用核心密钥生成 256 字节的置换盒（KSA 变体）。"""
    box = list(range(256))
    c = 0
    last = 0
    off = 0
    n = len(key)
    for i in range(256):
        swap = box[i]
        c = (swap + last + key[off]) & 0xFF
        off = (off + 1) % n
        box[i] = box[c]
        box[c] = swap
        last = c
    return bytes(box)


def _xor_mask_table(key_box: bytes) -> bytes:
    """预计算周期为 256 的异或掩码，用于对音频流做向量化解密。"""
    table = bytearray(256)
    for k in range(256):
        j = (k + 1) & 0xFF
        table[k] = key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xFF]) & 0xFF]
    return bytes(table)


def decrypt_audio(data: bytes, key_box: bytes) -> bytes:
    """
    解密音频流：
        out[i] = data[i] XOR keybox[(keybox[j] + keybox[(keybox[j] + j) & 0xff]) & 0xff]
    其中 j = (i + 1) & 0xff。因为掩码以 256 为周期，这里用大整数异或一次性完成，
    比逐字节循环快一到两个数量级。
    """
    if not data:
        return b""
    table = _xor_mask_table(key_box)
    reps = len(data) // 256 + 1
    mask = (table * reps)[:len(data)]
    n = len(data)
    return (int.from_bytes(data, "big") ^ int.from_bytes(mask, "big")).to_bytes(n, "big")


# ---------------------------------------------------------------------------
# 格式识别
# ---------------------------------------------------------------------------

def sniff_audio_format(audio: bytes) -> str:
    """根据魔术字节判断解密后的音频真实格式。"""
    if audio[:3] == b"ID3":
        return "mp3"
    if len(audio) > 1 and audio[0] == 0xFF and (audio[1] & 0xE0) == 0xE0:
        return "mp3"
    if audio[:4] == b"fLaC":
        return "flac"
    if audio[:4] == b"OggS":
        return "ogg"
    if audio[4:8] == b"ftyp":
        return "m4a"
    if audio[:4] == b"RIFF":
        return "wav"

    # 兜底：在前 256KB 内搜一下标记（少数文件前面可能有脏字节）
    head = audio[:256 * 1024]
    for sig, ext in ((b"ID3", "mp3"), (b"fLaC", "flac"), (b"OggS", "ogg")):
        if sig in head:
            return ext
    return "bin"


# ---------------------------------------------------------------------------
# 元数据
# ---------------------------------------------------------------------------

_BAD_FS = re.compile(r'[\\/:*?"<>|\r\n\t]')


def _safe_name(name: str, fallback: str) -> str:
    name = _BAD_FS.sub("_", name).strip().strip(".")
    name = re.sub(r"\s+", " ", name)
    if not name:
        return fallback
    # Windows 保留名
    if name.upper() in {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        name = "_" + name
    return name[:120]


def format_meta_name(meta: dict, fallback: str) -> str:
    """把元数据拼成 '歌名 - 歌手' 形式。"""
    song = (meta.get("musicName") or "").strip()
    artists = meta.get("artist") or []
    names = []
    for a in artists:
        if isinstance(a, (list, tuple)) and a:
            names.append(str(a[0]))
        elif isinstance(a, str):
            names.append(a)
    artist = "/".join(n for n in names if n)

    if song and artist:
        base = f"{song} - {artist}"
    elif song:
        base = song
    elif artist:
        base = artist
    else:
        base = fallback
    return _safe_name(base, fallback)


# ---------------------------------------------------------------------------
# 核心：解析并转换单个文件
# ---------------------------------------------------------------------------

class NcmError(Exception):
    pass


def _write_new(path: Path, data: bytes) -> bool:
    """原子地写入一个新文件；文件已存在则不动并返回 False。"""
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0))
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return True


def strip_pkcs7(b: bytes) -> bytes:
    """
    去掉 AES 分组加密留下的 PKCS7 填充字节。

    这一步必须做，而且很关键：密钥块明文的长度是不固定的（旧版是 17+16=33 字节，
    新版换成了 17+99=116 字节），AES 都会补齐到 16 的倍数，解密后如果不脱掉这些
    填充字节，拿去生成密钥盒就会得到一个错误的结果——解出来的音频全是噪声。
    """
    if not b:
        return b
    n = b[-1]
    if 1 <= n <= 16 and b[-n:] == bytes([n]) * n:
        return b[:-n]
    return b


def _commit(tmp_name: str, target_dir: Path, base: str, ext: str, src_path: Path) -> Path:
    """把一个已写好的临时文件改名成不冲突的正式文件名（os.rename 原子占位）。"""
    tmp = Path(tmp_name)
    src_key = str(src_path.resolve()).lower()
    try:
        n = 1
        while n <= 9999:
            p = target_dir / (f"{base}.{ext}" if n == 1 else f"{base} ({n}).{ext}")
            if str(p.resolve()).lower() == src_key:      # 别把源文件本身覆盖了
                n += 1
                continue
            try:
                os.rename(tmp, p)                        # 原子占位
                return p
            except FileExistsError:
                n += 1
                continue
            except PermissionError:
                if p.exists():                           # 名字被占用 → 换一个
                    n += 1
                    continue
                raise
        raise OSError(f"同名文件数量过多，放弃写入：{base}.{ext}")
    finally:
        if tmp.exists():
            try:
                tmp.unlink()                             # 中途失败别留垃圾
            except OSError:
                pass


def _write_unique(target_dir: Path, base: str, ext: str, data: bytes, src_path: Path) -> Path:
    """
    选一个不与已有文件冲突的名字写入，返回实际写入的路径。

    先把数据写到一个唯一命名的临时文件，再用 os.rename「占位」。Windows 上
    os.rename 在目标已存在时必定抛 FileExistsError，这一步是原子的 —— 所以多进程（-j）
    或多标签页同时转换同名歌曲时，谁先改名成功谁占用该名字，不会互相覆盖。
    """
    fd, tmp_name = tempfile.mkstemp(prefix=".ncm2mp3~", suffix=".part", dir=str(target_dir))
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return _commit(tmp_name, target_dir, base, ext, src_path)


def read_ncm(path: Path):
    """解析 NCM 文件，返回 (元数据 dict, 封面 bytes, 解密后的音频 bytes, 真实格式)。"""
    return parse_ncm(path.read_bytes())[:4]


def parse_ncm(raw: bytes, audio_head: int | None = None):
    """
    解析 NCM 数据，返回 (元数据, 封面, 音频, 真实格式, 布局信息)。

    audio_head 给定时只解密音频开头这么多字节 —— 用于快速读取元信息（封面/歌名/格式），
    不必把整段音频（可能几十 MB）都解出来。流密码的掩码以 256 为周期且从 0 开始，
    所以解密前缀得到的字节和全量解密完全一致。
    """
    layout = {"audio_start": 0, "enc_size": 0}
    if len(raw) < 32 or raw[:8] != NCM_MAGIC:
        raise NcmError("文件头不是 CTENFDAM，不是有效的 .ncm 文件")

    pos = 10
    if pos + 4 > len(raw):
        raise NcmError("文件损坏：读不到密钥块长度")
    key_len = struct.unpack_from("<I", raw, pos)[0]
    pos += 4
    if pos + key_len > len(raw):
        raise NcmError("文件损坏：密钥块长度越界")
    key_blob = bytes(b ^ KEY_XOR for b in raw[pos:pos + key_len])
    pos += key_len
    key_plain = aes128_ecb_decrypt(key_blob, CORE_KEY)[KEY_PREFIX_LEN:]
    # 必须脱掉 PKCS7 填充：新版 NCM 的真实音频密钥是一串 99 字节的 ASCII，
    # 旧版是 16 字节随机值，两者被 AES 补齐后的长度都不一样，带着填充去生成
    # 密钥盒就会得到错误的置换表，解出来的音频全是噪声。
    key_plain = strip_pkcs7(key_plain)
    if not key_plain:
        raise NcmError("文件损坏：解出来的音频密钥为空")

    if pos + 4 > len(raw):
        raise NcmError("文件损坏：读不到元数据长度")
    meta_len = struct.unpack_from("<I", raw, pos)[0]
    pos += 4
    if pos + meta_len > len(raw):
        raise NcmError("文件损坏：元数据长度越界")
    meta_blob = bytes(b ^ META_XOR for b in raw[pos:pos + meta_len])
    pos += meta_len

    meta: dict = {}
    if meta_len > 0:
        try:
            body = meta_blob[META_TAG_LEN:]
            # base64 长度若不是 4 的倍数，补齐后再解
            body += b"=" * (-len(body) % 4)
            decoded = base64.b64decode(body)
            plain = aes128_ecb_decrypt(decoded, META_KEY)[META_PREFIX_LEN:]
            # 注意：AES 分组解密结果尾部带 PKCS7 填充字节，
            # 直接 json.loads 会因"多余数据"报错，所以用 raw_decode 只取第一个 JSON 对象
            text = plain.decode("utf-8", "ignore")
            start = text.find("{")
            if start >= 0:
                meta, _ = json.JSONDecoder().raw_decode(text[start:])
        except Exception:
            meta = {}   # 元数据拿不到不影响音频转换

    pos += 5                                     # 5 字节填充
    if pos + 4 > len(raw):
        raise NcmError("文件损坏：读不到封面帧长度")
    cover_frame_len = struct.unpack_from("<I", raw, pos)[0]
    pos += 4

    if pos + 4 > len(raw):
        raise NcmError("文件损坏：读不到封面长度")
    img_len = struct.unpack_from("<I", raw, pos)[0]
    pos += 4
    if pos + img_len > len(raw):
        raise NcmError("文件损坏：封面长度越界")
    cover = raw[pos:pos + img_len]
    pos += img_len

    key_box = build_key_box(key_plain)

    # 封面帧长度通常刚好等于图片长度，但某些文件会多出一段填充。
    # 拿不准就两种对齐都试一次 —— 反正解出来的头部是不是合法音频一眼能看出来，
    # 这样既不会在常规文件上多花时间，也不会在少见文件上直接失败。
    starts = [pos]
    extra = cover_frame_len - img_len
    if 0 < extra < (1 << 20):                    # 上限 1MB，防止字段异常时跳飞
        starts.insert(0, pos + extra)

    audio = b""
    fmt = "bin"
    used_start = 0
    for start in starts:
        if start >= len(raw):
            continue
        window = raw[start:] if audio_head is None else raw[start:start + audio_head]
        cand = decrypt_audio(window, key_box)
        f = sniff_audio_format(cand)
        if f != "bin":
            audio, fmt, used_start = cand, f, start
            break

    if fmt == "bin":
        raise NcmError("解密后的数据不是可识别的音频（可能是新版加密变种，或文件不完整）")

    layout["audio_start"] = used_start
    layout["enc_size"] = len(raw) - used_start
    return meta, cover, audio, fmt, layout


# ---------------------------------------------------------------------------
# 元信息速读：拖进界面时用来显示封面 / 歌名 / 时长 / 大小
# ---------------------------------------------------------------------------

PROBE_HEAD = 288 * 1024        # 只解音频开头这么多字节（够覆盖格式嗅探的兜底搜索范围）
MAX_COVER_BYTES = 4 << 20      # 封面超过 4MB 就不往界面传了，避免 JSON 过大


def _cover_mime(cover: bytes) -> str:
    """判断封面图片类型；不是图片就返回空串。"""
    if cover[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if cover[:2] == b"\xff\xd8":
        return "image/jpeg"
    if cover[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if cover[:4] == b"RIFF" and cover[8:12] == b"WEBP":
        return "image/webp"
    return ""


def _mp3_bitrate(audio: bytes) -> int:
    """从第一帧的帧头读出比特率（bps）。读不到返回 0。"""
    i = 0
    if audio[:3] == b"ID3" and len(audio) >= 10:
        size = (((audio[6] & 0x7F) << 21) | ((audio[7] & 0x7F) << 14) |
                ((audio[8] & 0x7F) << 7) | (audio[9] & 0x7F))
        i = 10 + size
    while i + 4 <= len(audio):
        if audio[i] == 0xFF and (audio[i + 1] & 0xE0) == 0xE0:
            break
        i += 1
    if i + 4 > len(audio):
        return 0
    h = audio[i:i + 4]
    ver = (h[1] >> 3) & 0x03            # 3=MPEG1, 2=MPEG2, 0=MPEG2.5
    layer = (h[1] >> 1) & 0x03          # 1=Layer III
    idx = (h[2] >> 4) & 0x0F
    if layer != 1 or idx in (0, 15):
        return 0
    mpeg1 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
    mpeg2 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0]
    return (mpeg1 if ver == 3 else mpeg2)[idx] * 1000


def _flac_duration_ms(audio: bytes) -> int:
    """
    FLAC 总时长可以直接从 STREAMINFO 里算出来，不用扫全文件。

    结构：'fLaC' + 4 字节块头 + 34 字节 STREAMINFO，
    采样率(20bit) 和总采样数(36bit) 位于 STREAMINFO 的第 10..17 字节。
    """
    if audio[:4] != b"fLaC" or len(audio) < 26:
        return 0
    if (audio[4] & 0x7F) != 0:          # 第一个块必须是 STREAMINFO
        return 0
    b = audio[18:26]
    rate = (b[0] << 12) | (b[1] << 4) | (b[2] >> 4)
    total = ((b[3] & 0x0F) << 32) | (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]
    if rate <= 0 or total <= 0:
        return 0
    return int(total * 1000 / rate)


def _guess_duration_ms(meta: dict, fmt: str, audio: bytes, enc_size: int) -> int:
    """估时长（毫秒）。估不出来就返回 0，界面显示成「—」，不编造数字。"""
    d = meta.get("duration")
    if isinstance(d, (int, float)) and d > 0:
        return int(d)                                  # 文件自带的，最准
    if fmt == "flac":
        ms = _flac_duration_ms(audio)
        if ms:
            return ms
    if fmt == "mp3":
        br = _mp3_bitrate(audio)
        if br:
            return int(enc_size * 8 / br * 1000)       # CBR 下这个推算相当准
    br = meta.get("bitrate")
    if isinstance(br, (int, float)) and br > 0:
        return int(enc_size * 8 / br * 1000)
    return 0


def probe_ncm(path: Path) -> dict:
    """
    快速读取一个 .ncm 的元信息：歌名、歌手、专辑、时长、码率、封面、真实格式。

    只解音频开头一小段用于判断格式，不整段解密 —— 所以几十 MB 的文件也是毫秒级。
    """
    raw = path.read_bytes()
    meta, cover, head, fmt, layout = parse_ncm(raw, audio_head=PROBE_HEAD)

    artists = []
    for a in (meta.get("artist") or []):
        if isinstance(a, (list, tuple)) and a:
            artists.append(str(a[0]))
        elif isinstance(a, str):
            artists.append(a)

    mime = _cover_mime(cover)
    cover_url = ""
    if mime and 0 < len(cover) <= MAX_COVER_BYTES:
        cover_url = "data:%s;base64,%s" % (
            mime, base64.b64encode(cover).decode("ascii"))

    bitrate = 0
    b = meta.get("bitrate")
    if isinstance(b, (int, float)) and b > 0:
        bitrate = int(b)
    elif fmt == "mp3":
        bitrate = _mp3_bitrate(head)

    return {
        "title": (meta.get("musicName") or "").strip() or _safe_name(path.stem, "audio"),
        "artist": "/".join(artists),
        "album": (meta.get("album") or "").strip(),
        "duration": _guess_duration_ms(meta, fmt, head, layout["enc_size"]),
        "bitrate": bitrate,
        "fmt": fmt,
        "size": len(raw),
        "cover": cover_url,
    }


def convert_one(src: str, out_dir: str | None, want_cover: bool,
                to_mp3: bool, ffmpeg: str | None):
    """转换单个文件。返回 (是否成功, 描述信息, 输出文件路径或 None)。"""
    t0 = time.time()
    src_path = Path(src)
    fallback = _safe_name(src_path.stem, "audio")
    try:
        meta, cover, audio, fmt = read_ncm(src_path)
    except NcmError as e:
        return False, f"[跳过] {src_path.name} -> {e}", None
    except Exception as e:
        return False, f"[失败] {src_path.name} -> {type(e).__name__}: {e}", None

    base = format_meta_name(meta, fallback)
    target_dir = Path(out_dir) if out_dir else src_path.parent
    target_dir.mkdir(parents=True, exist_ok=True)

    ext = fmt
    if to_mp3 and fmt != "mp3":
        if not ffmpeg:
            return False, f"[失败] {src_path.name} -> 源格式是 {fmt}，强制转 mp3 需要 ffmpeg（未找到）", None
        tmp_in = target_dir / f".{base}.{fmt}.tmp"
        tmp_in.write_bytes(audio)
        # ffmpeg 先输出到临时文件，再走同一套原子改名，避免并发时互相覆盖
        fd, tmp_out = tempfile.mkstemp(prefix=".ncm2mp3~", suffix=".part", dir=str(target_dir))
        os.close(fd)
        try:
            try:
                subprocess.run(
                    [ffmpeg, "-hide_banner", "-loglevel", "error", "-y",
                     "-i", str(tmp_in), "-vn", "-codec:a", "libmp3lame", "-q:a", "0",
                     tmp_out],
                    check=True, capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                msg = (e.stderr or b"").decode("utf-8", "ignore").strip()[:200]
                return False, f"[失败] {src_path.name} -> ffmpeg 转码失败: {msg}", None
            except OSError as e:
                return False, f"[失败] {src_path.name} -> 调用 ffmpeg 出错: {e}", None
            out_path = _commit(tmp_out, target_dir, base, "mp3", src_path)
        finally:
            tmp_in.unlink(missing_ok=True)
            try:
                os.unlink(tmp_out)                       # 成功改名后这里已不存在，忽略即可
            except OSError:
                pass
        ext = "mp3"
    else:
        out_path = _write_unique(target_dir, base, ext, audio, src_path)

    cover_note = ""
    if want_cover and cover:
        if cover[:8] == bytes.fromhex("89504e470d0a1a0a"):     # PNG
            cext = ".png"
        elif cover[:2] == b"\xff\xd8":                         # JPEG
            cext = ".jpg"
        else:
            cext = None
        if cext:
            # 封面跟着音频文件名走，避免同名歌曲（X.mp3 / X (2).mp3）互相覆盖封面
            try:
                if _write_new(out_path.with_suffix(cext), cover):
                    cover_note = " +封面"
            except OSError:
                pass                                            # 封面是附加品，写不进去不影响音频

    mb = len(audio) / 1024 / 1024
    return True, f"[完成] {src_path.name} -> {out_path.name}  ({fmt}, {mb:.1f}MB, {time.time() - t0:.1f}s){cover_note}", out_path


# ---------------------------------------------------------------------------
# 批量调度
# ---------------------------------------------------------------------------

def collect_inputs(targets: list[str]) -> list[str]:
    files: list[str] = []
    for t in targets:
        p = Path(t)
        if p.is_dir():
            files += [str(x) for x in sorted(p.rglob("*.ncm"))]
        elif p.is_file():
            files.append(str(p))
        else:
            print(f"[警告] 路径不存在：{t}")
    # 去重并保持顺序
    seen = set()
    out = []
    for f in files:
        k = str(Path(f).resolve()).lower()
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# 本地网页控制台（只用标准库 http.server，不需要 tkinter / 第三方包）
# ---------------------------------------------------------------------------

_GUI_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NCM 转换器</title>
<style>
:root{--bg:#f5f5f7;--card:#fff;--fg:#1b1b1e;--muted:#71717a;--line:#e4e4e8;--accent:#3b6fd4;--ok:#118a56;--err:#c8403a}
@media (prefers-color-scheme:dark){:root{--bg:#151517;--card:#1e1e21;--fg:#ececf0;--muted:#9a9aa3;--line:#2e2e34;--accent:#5b8ee8;--ok:#3fbf7f;--err:#e0685f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
.wrap{max-width:880px;margin:0 auto;padding:30px 20px 64px}
h1{font-size:21px;font-weight:600;margin:0 0 5px}
.sub{color:var(--muted);font-size:13px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:16px}
.card h2{font-size:14px;font-weight:600;margin:0 0 4px}
p.hint{color:var(--muted);font-size:12px;margin:0 0 14px}
#drop{border:1.5px dashed var(--line);border-radius:10px;padding:36px 16px;text-align:center;cursor:pointer;transition:border-color .15s,background .15s}
#drop.on{border-color:var(--accent);background:rgba(91,142,232,.09)}
#drop .big{font-size:15px;font-weight:500;margin-bottom:5px}
#drop .sm{color:var(--muted);font-size:12px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:14px}
button{font:inherit;padding:7px 14px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
button:hover:not(:disabled){border-color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button:disabled{opacity:.45;cursor:default}
label.chk{display:flex;gap:6px;align-items:center;color:var(--muted);font-size:13px;cursor:pointer}
input[type=text]{font:inherit;padding:7px 10px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);width:100%}
#bar{height:5px;background:var(--line);border-radius:3px;overflow:hidden;margin-top:16px;display:none}
#bar>i{display:block;height:100%;width:0;background:var(--accent);transition:width .2s}
.stat{color:var(--muted);font-size:12px;margin-top:10px;min-height:18px}
#list,#list2{margin-top:6px}
.item{display:flex;gap:12px;padding:7px 0;border-top:1px solid var(--line);font-size:13px;align-items:baseline}
.item .n{flex:1;word-break:break-all}
.item .s{font-size:12px;white-space:nowrap;color:var(--muted)}
.ok{color:var(--ok)!important}.err{color:var(--err)!important}
#queue{margin-top:14px}
.qitem{display:flex;gap:12px;align-items:center;padding:9px 10px;border:1px solid var(--line);border-radius:10px;margin-top:8px;background:var(--bg)}
.qitem.bad{border-color:var(--err)}
.qitem .cov{width:50px;height:50px;flex:none;border-radius:8px;object-fit:cover;background:var(--line);display:block}
.qitem .cov.ph{display:flex;align-items:center;justify-content:center;font-size:10px;color:var(--muted);line-height:1.2;text-align:center}
.qitem .mid{flex:1;min-width:0}
.qitem .t{font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.qitem.bad .t{color:var(--err)}
.qitem .a{color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.qitem .d{color:var(--muted);font-size:11px;margin-top:1px}
.qitem .rm{flex:none;width:30px;height:30px;padding:0;font-size:17px;line-height:1;color:var(--muted);border-radius:8px}
.qitem .rm:hover:not(:disabled){color:var(--err);border-color:var(--err)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:640px){.grid{grid-template-columns:1fr}}
.f{margin-bottom:12px}
.f>label{display:block;font-size:12px;color:var(--muted);margin-bottom:5px}
.pathrow{display:flex;gap:8px}
.pathrow input{flex:1;min-width:0}
.pathrow button{white-space:nowrap}
/* 「选择文件夹」的提示条：找不到窗口 / 没选目录时给用户一条出路 */
.pickhint{font-size:12px;margin-top:8px;color:var(--muted);
  display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.pickhint.warn{color:var(--err)}
.pickhint a{color:inherit;text-decoration:none;border-bottom:1px dotted currentColor;cursor:pointer}
.pickhint a:hover{border-bottom-style:solid}
.foot{text-align:center;color:var(--muted);font-size:12px;margin-top:22px}
.foot a{color:var(--muted);text-decoration:none;border-bottom:1px dotted var(--muted)}
.foot a:hover{color:var(--err);border-color:var(--err)}
.sig{margin-top:9px;font-size:11px;letter-spacing:.3px}
</style>
</head>
<body>
<div class="wrap">
  <h1>NCM 转换器</h1>
  <div class="sub">全部在本机运行，文件不会上传到任何服务器</div>

  <div class="card">
    <h2>拖拽导出</h2>
    <p class="hint">一次可以拖多个 .ncm 文件，也支持直接拖整个文件夹。拖进来会读出封面、歌名、时长和大小，点右侧的 × 可以把某个文件移出队列</p>
    <div id="drop">
      <div class="big">把 .ncm 文件拖到这里</div>
      <div class="sm">支持多选，也支持直接拖文件夹</div>
    </div>
    <input type="file" id="pick" multiple accept=".ncm" hidden>
    <div id="queue"></div>
    <div class="f" style="margin:14px 0 0">
      <label>导出到（转换完直接存到这里）</label>
      <div class="pathrow">
        <input type="text" id="outdir" value="__OUTDIR__">
        <button id="browse">选择文件夹…</button>
      </div>
      <div id="pickhint" class="pickhint" hidden></div>
    </div>
    <div class="row">
      <button id="go" class="primary" disabled>开始导出</button>
      <button id="reveal" disabled>打开输出文件夹</button>
      <button id="zip" disabled>打包下载</button>
      <button id="clr">清空</button>
      <label class="chk"><input type="checkbox" id="cover"> 顺便导出封面</label>
      <label class="chk"><input type="checkbox" id="tomp3"> flac 也转成 mp3</label>
    </div>
    <div id="bar"><i></i></div>
    <div id="stat" class="stat"></div>
    <div id="list"></div>
  </div>

  <div class="card">
    <h2>本地目录模式</h2>
    <p class="hint">适合一整批文件的场景，直接在原目录里转换，不复制、不下载。路径可以从资源管理器地址栏直接复制粘贴</p>
    <div class="grid">
      <div class="f">
        <label>要扫描的目录</label>
        <div class="pathrow">
          <input type="text" id="src" placeholder="D:\Music\ncm">
          <button id="browseSrc">选择文件夹…</button>
        </div>
      </div>
      <div class="f">
        <label>输出目录（留空 = 与原文件同目录）</label>
        <div class="pathrow">
          <input type="text" id="dst" placeholder="留空即可">
          <button id="browseDst">选择文件夹…</button>
        </div>
      </div>
    </div>
    <div id="pickhint2" class="pickhint" hidden></div>
    <div class="row">
      <button id="scan">先扫描看看</button>
      <button id="goDir" class="primary">转换这个目录</button>
    </div>
    <div id="stat2" class="stat"></div>
    <div id="list2"></div>
  </div>

  <div class="foot">
    <a href="#" id="quit">退出程序</a>
    <div class="sig">Na1aB 做的格式转换小工具 v1.0</div>
  </div>
</div>
<script>
var T = "__TOKEN__";
function $(id){ return document.getElementById(id); }
function api(u){ return "/" + T + u; }
var list = $("list"), bar = $("bar"), stat = $("stat");

$("drop").onclick = function(){ $("pick").click(); };
$("pick").onchange = function(e){ addFiles(Array.prototype.slice.call(e.target.files)); e.target.value = ""; };

function walk(entry, out){
  return new Promise(function(res){
    if (entry.isFile) { entry.file(function(f){ out.push(f); res(); }, res); }
    else if (entry.isDirectory) {
      var rd = entry.createReader();
      var read = function(){
        rd.readEntries(function(ents){
          if (!ents.length) return res();
          var chain = Promise.resolve();
          ents.forEach(function(en){ chain = chain.then(function(){ return walk(en, out); }); });
          chain.then(read);
        }, res);
      };
      read();
    } else res();
  });
}

["dragenter","dragover"].forEach(function(ev){
  $("drop").addEventListener(ev, function(e){ e.preventDefault(); $("drop").classList.add("on"); });
});
["dragleave","drop"].forEach(function(ev){
  $("drop").addEventListener(ev, function(e){ e.preventDefault(); $("drop").classList.remove("on"); });
});
$("drop").addEventListener("drop", function(e){
  var dt = e.dataTransfer, entries = dt.items, out = [];
  if (entries && entries.length && entries[0].webkitGetAsEntry) {
    var chain = Promise.resolve();
    Array.prototype.forEach.call(entries, function(it){
      var en = it.webkitGetAsEntry();
      if (en) chain = chain.then(function(){ return walk(en, out); });
    });
    chain.then(function(){ addFiles(out); });
  } else {
    addFiles(Array.prototype.slice.call(dt.files));
  }
});

// ---------------- 队列 ----------------
// 拖进来的文件会先上传一次读出封面/歌名/时长/大小，之后点「开始导出」直接用
// 缓存好的那份，不会重复传输。每一项右侧的 × 可以单独从队列里移除。
var items = [];          // {uid, key, file, id, info, note, bad}
var uidSeq = 0;
var pending = [];        // 等待读取信息的项
var pumping = false;
var busyConverting = false;

function esc(s){
  return String(s).replace(/[&<>"]/g, function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c];
  });
}
function sz(n){ return n < 1048576 ? (n/1024).toFixed(0) + " KB" : (n/1048576).toFixed(1) + " MB"; }
function hm(ms){
  if (!ms) return "";
  var t = Math.round(ms/1000), m = Math.floor(t/60), s = t%60;
  return (m<10?"0":"") + m + ":" + (s<10?"0":"") + s;
}

function addFiles(arr){
  var named = 0;
  arr.forEach(function(f){
    if (!/\.ncm$/i.test(f.name)) return;
    named++;
    addItem(f);
  });
  updateStat();
  if (arr.length && !named) {
    stat.textContent = "拖进来的 " + arr.length + " 个文件里没有 .ncm（只认 .ncm 后缀）";
  }
}

function addItem(file){
  var key = file.name + "|" + file.size;
  for (var i = 0; i < items.length; i++) {
    if (items[i].key === key) return;                 // 同一个文件不重复入队
  }
  var it = {uid: ++uidSeq, key: key, file: file, id: "", info: null, note: "读取中…", bad: false};
  items.push(it);
  pending.push(it);
  renderQueue();
  pump();
}

// 告诉服务端"这几份临时文件我不要了"，让它立刻删掉，不等一小时后自动清扫
function dropIds(ids){
  if (!ids || !ids.length) return;
  fetch(api("/api/drop"), { method: "POST", headers: {"Content-Type": "application/json"},
                            body: JSON.stringify({ ids: ids }) }).catch(function(){});
}

function removeItem(uid, silent){
  var gone = null;
  for (var i = 0; i < items.length; i++) {
    if (items[i].uid === uid) { gone = items.splice(i, 1)[0]; break; }
  }
  if (!gone) return;
  pending = pending.filter(function(x){ return x.uid !== uid; });
  if (gone.id) dropIds([gone.id]);
  if (!silent) { renderQueue(); updateStat(); }
}

// 清空队列。
// 注意：这里**绝对不能**写成 items.forEach(function(it){ removeItem(it.uid); })。
// removeItem 内部是 splice，而 forEach 是按下标递增 + 每步重读 length 的，
// 删掉当前项会让后面所有元素左移一格 → 下一次迭代直接跳过一个元素。
// 结果就是：4 个文件只会删掉 2 个，剩 2 个再点一次只删 1 个（用户实测到的现象，
// 删掉的数量正好是 ceil(n/2)）。所以这里整数组一次性换掉，不做逐个 splice。
function clearAll(){
  var n = items.length;
  var ids = [];
  for (var i = 0; i < n; i++) if (items[i].id) ids.push(items[i].id);

  items = [];                 // 原生数组，不用 Array.prototype.forEach 边遍历边删
  pending = [];               // 还没读完的也一并作废，pump() 会自己停下
  renderQueue();              // items 空 → 直接清干净 DOM
  $("queue").innerHTML = "";

  updateStat();               // 会按 n=0 把「开始导出」「清空」都置灰
  list.innerHTML = "";        // 顺带把上次的转换结果列表清掉
  bar.style.display = "none";
  stat.textContent = "";
  $("zip").disabled = true;
  $("reveal").disabled = true;
  setHint(pickHint, "");

  dropIds(ids);               // 一次性通知服务端，不再逐个发请求
  return n;
}

// 串行读取：一次只处理一个，拖几十个文件时不会把内存和带宽打满
function pump(){
  if (pumping) return;
  var it = pending.shift();
  if (!it) return;
  if (items.indexOf(it) < 0) return pump();           // 已经被移除的跳过
  pumping = true;
  fetch(api("/api/info") + "?name=" + encodeURIComponent(it.file.name),
        { method: "POST", body: it.file })
    .then(function(r){ return r.json(); })
    .then(function(j){
      // 请求回来的这一刻，这一项可能已经被「清空」或 × 掉了。
      // 那样服务端刚存下的临时文件就没人认领了（要等一小时后才清扫），这里马上回收。
      if (items.indexOf(it) < 0) { if (j && j.id) dropIds([j.id]); return; }
      if (j.ok) {
        it.id = j.id; it.info = j.info; it.note = ""; it.bad = false;
      } else {
        it.bad = true; it.note = j.msg || "读取失败";
      }
    })
    .catch(function(){ it.bad = true; it.note = "读取失败：请求出错"; })
    .then(function(){ pumping = false; renderQueue(); updateStat(); pump(); });
}

function renderQueue(){
  var box = $("queue");
  if (!items.length) { box.innerHTML = ""; return; }
  var html = "";
  items.forEach(function(it){
    var inf = it.info || {};
    var cov = inf.cover
      ? '<img class="cov" src="' + inf.cover + '" alt="">'
      : '<div class="cov ph">' + (it.id ? "无<br>封面" : "读取<br>中") + '</div>';

    var sub = [inf.artist, inf.album].filter(Boolean).join(" · ");
    if (!sub) sub = inf.fmt ? (inf.fmt.toUpperCase() + " 音频") : (it.file.name);

    var meta = [];
    if (inf.duration) meta.push(hm(inf.duration));
    if (inf.bitrate) meta.push(Math.round(inf.bitrate/1000) + " kbps");
    if (inf.fmt) meta.push(inf.fmt.toUpperCase());
    meta.push(sz(it.file.size));

    var line3 = it.bad
      ? '<span class="err">' + esc(it.note) + '</span>'
      : (it.id ? esc(meta.join(" · "))
               : '<span style="opacity:.7">正在读取文件信息…</span>');

    html += '<div class="qitem' + (it.bad ? " bad" : "") + '" data-uid="' + it.uid + '">'
          +   cov
          +   '<div class="mid">'
          +     '<div class="t">' + esc(inf.title || it.file.name) + '</div>'
          +     '<div class="a">' + esc(sub) + '</div>'
          +     '<div class="d">' + line3 + '</div>'
          +   '</div>'
          +   '<button class="rm" title="从队列移除">\u00d7</button>'
          + '</div>';
  });
  box.innerHTML = html;
}

$("queue").onclick = function(e){
  var btn = e.target && e.target.closest ? e.target.closest(".rm") : null;
  if (!btn) return;
  removeItem(parseInt(btn.parentNode.getAttribute("data-uid"), 10));
};

function updateStat(showQueue){
  var n = items.length;
  var reading = items.filter(function(x){ return !x.id && !x.bad; }).length;
  if (showQueue !== false) {
    if (!n) {
      stat.textContent = "";
    } else {
      var total = items.reduce(function(a, x){ return a + x.file.size; }, 0);
      stat.textContent = "队列 " + n + " 个文件，共 " + sz(total)
                       + (reading ? "　·　还有 " + reading + " 个正在读取…" : "");
    }
  }
  $("go").disabled = busyConverting || !n || reading > 0;
  $("clr").disabled = busyConverting || !n;
}

$("clr").onclick = function(){
  if (busyConverting) return;      // 转换中按钮本来就是灰的，这里再兜一道
  clearAll();
};

/* ---------- 选择文件夹（通用，三处共用） ----------
   导出目录、要扫描的目录、输出目录都用这一套。

   对话框是后台子进程建的，有时候会被挡在其他窗口后面（尤其是 App 窗口最大化时）。
   所以这里：15 秒没见到结果就在下面给一条「强制关闭」的出路，
   万一真的没弹出来，用户也不会被一个禁用的按钮卡死。

   同一时刻只允许开一个对话框：后端在 picker 还活着时会直接拒掉第二个请求
   （否则两个 PowerShell 对话框叠在一起，用户点哪个都晕）。 */
var pickHint = $("pickhint");
var pickHint2 = $("pickhint2");
var pickOpen = false;

function setHint(el, html, warn) {
  if (!el) return;
  if (!html) { el.hidden = true; el.innerHTML = ""; return; }
  el.hidden = false;
  el.className = "pickhint" + (warn ? " warn" : "");
  el.innerHTML = html;
}

function bindPick(btnId, inputId, hintEl, desc, onPicked) {
  var b = $(btnId), input = $(inputId);
  var label = b.textContent;

  function kill() {
    setHint(hintEl, "正在关闭…");
    fetch(api("/api/pick-cancel"), { method: "POST" }).catch(function(){});
  }

  b.onclick = function(){
    if (pickOpen) {
      setHint(hintEl, "已经有选择窗口开着了，先把它关掉再点这里", true);
      return;
    }
    pickOpen = true;
    b.disabled = true; b.textContent = "选择中…";
    setHint(hintEl, "正在等你选目录…（窗口已弹出的话，它一定在最前面）" +
                    '<a class="kill">没看到窗口？点这里强制关闭</a>');
    hintEl.querySelector(".kill").onclick = kill;

    var slow = setTimeout(function(){
      if (b.disabled) {
        setHint(hintEl, "还没选好吗？如果屏幕上确实没有「浏览文件夹」窗口，" +
                        "点上面的强制关闭，或者直接在输入框里粘贴路径。" +
                        '<a class="kill2">强制关闭</a>', true);
        hintEl.querySelector(".kill2").onclick = kill;
      }
    }, 15000);

    fetch(api("/api/pick"), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: input.value.trim(), desc: desc })
    })
      .then(function(r){ return r.json(); })
      .then(function(j){
        if (j.ok) {
          input.value = j.path;
          // 手动派发一次 input，让监听这个框的逻辑（比如"目录变了就清旧结果"）
          // 也能被触发 —— 直接改 .value 是不会触发 oninput 的。
          try { input.dispatchEvent(new Event("input", { bubbles: true })); } catch (e) {}
          setHint(hintEl, "");
          if (onPicked) onPicked(j.path);
          return;
        }
        var msg = j.msg || "没有选择目录";
        if (!j.busy) msg += "（也可以直接在输入框里粘贴路径）";
        setHint(hintEl, msg, !!j.busy);
      })
      .catch(function(e){ setHint(hintEl, "调用系统对话框失败：" + e + "（可直接在输入框里粘贴路径）", true); })
      .then(function(){
        clearTimeout(slow);
        pickOpen = false;
        b.disabled = false; b.textContent = label;
      });
  };
}

bindPick("browse",    "outdir", pickHint,  "选择转换后文件的保存位置");
bindPick("browseDst", "dst",    pickHint2, "选择转换后的输出目录");
// 选完扫描目录就直接扫一遍，省得再点一次「先扫描看看」
bindPick("browseSrc", "src",    pickHint2, "选择要扫描的 .ncm 目录",
         function(){ $("scan").click(); });

$("reveal").onclick = function(){
  fetch(api("/api/reveal"), { method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: $("outdir").value.trim() }) });
};

$("quit").onclick = function(e){
  e.preventDefault();
  if (!confirm("确定退出程序？退出后这个页面就不能用了，需要重新运行才能恢复。")) return;
  fetch(api("/api/quit"), { method: "POST" }).catch(function(){}).then(function(){
    document.body.innerHTML =
      '<div class="wrap"><h1>已退出</h1>' +
      '<div class="sub">程序已关闭，这个页面可以关掉了</div></div>';
  });
};

$("go").onclick = function(){
  var ready = items.filter(function(x){ return x.id; });
  if (!ready.length) return;
  var go = $("go"), zip = $("zip"), clr = $("clr");
  busyConverting = true;
  go.disabled = true; zip.disabled = true; clr.disabled = true;
  bar.style.display = "block"; list.innerHTML = "";
  var ok = 0, bad = 0, i = 0, lastDir = "", warned = false;

  function step(){
    if (i >= ready.length) {
      busyConverting = false;
      bar.firstElementChild.style.width = "100%";
      if (lastDir) $("reveal").disabled = (ok === 0);
      zip.disabled = ok === 0;
      zip.onclick = function(){ location.href = api("/api/zip"); };
      updateStat(false);            // 只刷新按钮状态，别把下面这句结论冲掉
      stat.textContent = "完成：成功 " + ok + " 个，失败 " + bad + " 个"
                       + (lastDir ? "　·　已保存到 " + lastDir : "");
      return;
    }
    var it = ready[i];
    bar.firstElementChild.style.width = (i / ready.length * 100) + "%";
    stat.textContent = "转换中 " + (i + 1) + "/" + ready.length + "：" +
                       ((it.info && it.info.title) || it.file.name);

    var row = document.createElement("div");
    row.className = "item";
    var nm = document.createElement("div"); nm.className = "n";
    nm.textContent = (it.info && it.info.title) || it.file.name;
    var st = document.createElement("div"); st.className = "s"; st.textContent = "处理中…";
    row.appendChild(nm); row.appendChild(st);
    list.insertBefore(row, list.firstChild);

    var q = "?id=" + encodeURIComponent(it.id)
          + "&cover=" + ($("cover").checked ? "1" : "0")
          + "&to_mp3=" + ($("tomp3").checked ? "1" : "0")
          + "&out=" + encodeURIComponent($("outdir").value.trim());
    fetch(api("/api/convert") + q, { method: "POST" })
      .then(function(r){ return r.json(); })
      .then(function(j){
        if (j.ok) {
          ok++;
          if (j.dir) lastDir = j.dir;
          if (j.fallback && !warned) {
            warned = true;
            alert("你填的导出目录没法写入，文件被临时存到了系统临时文件夹。\n请换一个目录（比如 D:\\Music）再试一次。");
          }
          nm.textContent = j.out;
          st.className = "s ok";
          st.textContent = "→ " + j.fmt + " " + j.mb + "MB";
          removeItem(it.uid, true);          // 转完就从队列里拿走
        } else {
          bad++;
          st.className = "s err";
          st.textContent = j.msg.replace(/^\[[^\]]*\]\s*/, "");
        }
      })
      .catch(function(e){ bad++; st.className = "s err"; st.textContent = "请求失败：" + e; })
      .then(function(){ i++; renderQueue(); step(); });
  }
  step();
};

/* ---------------- 本地目录模式 ----------------
   「换了目录，列表还是旧的」有两种成因，这里都堵住：

   1) 上一次扫描的响应晚到
      扫描是异步的。如果换了目录马上再点一次，两个请求同时在飞，
      旧目录那次要是后到，就会把新目录的结果盖掉（或者接在后面），
      看起来就是"点了扫描还是显示原来目录的文件"。
      做法：每次扫描发一个递增序号，回来时不是最新那次就直接丢弃。

   2) 改了目录但没重新扫，旧结果一直挂在下面
      输入框内容一变，就把上一次的结果清掉并提示重扫 —— 这样永远不会
      出现"界面上摆着别的目录的文件"这种自相矛盾的状态。

   另外状态行里带上**实际扫的是哪个目录**，一眼就能看出有没有生效。 */
var scanSeq = 0;          // 扫描请求序号，只认最新那次
var scanPath = "";        // 上一次真正扫成功的是哪个目录

function clearScan(msg) {
  scanPath = "";
  $("list2").innerHTML = "";
  if (msg !== undefined) $("stat2").textContent = msg;
}

// 目录一改，上一次的扫描结果就作废（不然界面上会摆着别的目录的文件）
function onSrcMaybeChanged(){
  if (scanPath && $("src").value.trim() !== scanPath) {
    clearScan("目录已经改了，点「先扫描看看」重新扫一遍");
  }
}
$("src").oninput = onSrcMaybeChanged;

$("scan").onclick = function(){
  var p = $("src").value.trim();
  if (!p) { clearScan("请先填写目录路径（右边可以直接点「选择文件夹…」）"); return; }

  var my = ++scanSeq;               // 本次扫描的身份证
  scanPath = "";
  $("stat2").textContent = "扫描中…";
  $("list2").innerHTML = "";

  fetch(api("/api/scan"), { method: "POST", headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ path: p }) })
    .then(function(r){ return r.json(); })
    .then(function(j){
      if (my !== scanSeq) return;   // 期间又点了别的目录，这次的结果已经过期，丢掉
      if (!j.ok) { $("stat2").textContent = j.msg; return; }
      scanPath = p;
      $("stat2").textContent = "找到 " + j.files.length + " 个 .ncm 文件　·　目录：" + p;
      j.files.slice(0, 300).forEach(function(f){
        var d = document.createElement("div"); d.className = "item";
        var n = document.createElement("div"); n.className = "n"; n.textContent = f;
        d.appendChild(n); $("list2").appendChild(d);
      });
      if (j.files.length > 300) {
        var d = document.createElement("div"); d.className = "item";
        d.textContent = "… 还有 " + (j.files.length - 300) + " 个未列出";
        $("list2").appendChild(d);
      }
    })
    .catch(function(e){
      if (my !== scanSeq) return;
      $("stat2").textContent = "请求失败：" + e;
    });
};

$("goDir").onclick = function(){
  var p = $("src").value.trim();
  if (!p) { clearScan("请先填写目录路径（右边可以直接点「选择文件夹…」）"); return; }
  var dst = $("dst").value.trim();
  $("goDir").disabled = true;
  $("stat2").textContent = "转换中，文件多时请耐心等待…";
  $("list2").innerHTML = "";
  scanPath = "";                    // 这次列的是转换结果，不是扫描结果
  fetch(api("/api/convert-path"), { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: p, out: dst,
                               cover: $("cover").checked, to_mp3: $("tomp3").checked }) })
    .then(function(r){ return r.json(); })
    .then(function(j){
      $("goDir").disabled = false;
      $("stat2").textContent = j.msg + "　·　目录：" + p + "　·　输出：" + (dst || "与原文件同目录");
      (j.results || []).forEach(function(x){
        var d = document.createElement("div"); d.className = "item";
        var n = document.createElement("div"); n.className = "n"; n.textContent = x.name;
        var s = document.createElement("div"); s.className = "s " + (x.ok ? "ok" : "err");
        s.textContent = x.note.replace(/^\[[^\]]*\]\s*/, "");
        d.appendChild(n); d.appendChild(s); $("list2").appendChild(d);
      });
    })
    .catch(function(e){ $("goDir").disabled = false; $("stat2").textContent = "请求失败：" + e; });
};

// 窗口被关掉时告诉后端一声，好让程序跟着退出（不然它会一直挂后台）。
// sendBeacon 是浏览器专门为「页面即将消失」设计的，比 fetch 可靠。
// 注意：刷新页面也会触发这里，但刷新会立刻重新加载，后端收到新的页面请求就会撤销退出。
window.addEventListener("pagehide", function(){
  try { navigator.sendBeacon(api("/api/bye")); } catch (e) {}
});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# 用「应用窗口」模式打开界面
#
# 背景：界面是网页，如果丢给系统默认浏览器，会带上地址栏和一堆标签页，观感不像
# 一个独立程序。而基于 Chromium 的浏览器（Edge / Chrome）有一个 --app=URL 参数，
# 能把页面开成一个没有地址栏、没有标签页的独立窗口，看起来就是个原生程序。
#
# 这两个函数都只用标准库：os.environ 读环境变量、winreg 读注册表、ctypes 拿屏幕尺寸。
# 刻意不调用 reg.exe —— 有些环境会把它拦掉，而且多开一个进程也没必要。
# ---------------------------------------------------------------------------

def _chromium_guess_paths() -> list[str]:
    """Edge / Chrome 的常见安装位置（注册表里翻不到时的兜底）。"""
    out: list[str] = []
    for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA"):
        base = os.environ.get(env)
        if not base:
            continue
        out.append(os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"))
        out.append(os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"))
    return out


def find_app_browser() -> str | None:
    """
    找一个能开独立应用窗口的 Chromium 浏览器，找到就返回它的完整路径。

    顺序：注册表 App Paths（最准，装到非默认目录也能找到）→ 常见安装路径。
    返回 None 表示这台机器没有 Edge 也没有 Chrome，调用方应退回默认浏览器。
    """
    if os.name != "nt":
        return None

    try:
        import winreg
        for exe in ("msedge.exe", "chrome.exe"):
            for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                    try:
                        key = winreg.OpenKey(
                            root,
                            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exe,
                            0, winreg.KEY_READ | view)
                    except OSError:
                        continue
                    try:
                        val = winreg.QueryValue(key, None)
                    finally:
                        key.Close()
                    if val and Path(val).is_file():
                        return str(Path(val))
    except Exception:
        pass

    for cand in _chromium_guess_paths():
        if Path(cand).is_file():
            return cand
    return None


def _screen_size() -> tuple[int, int]:
    """
    可用桌面尺寸（已排除任务栏），拿不到就按 1920x1080 算。

    刻意不调用 SetProcessDPIAware：Chromium 的 --window-size 用的是**逻辑像素**
    （DIP），这里保持一致才能算出正确比例。声明 DPI 感知反而会拿到物理像素 ——
    在 4K + 200% 缩放的机器上，算出来的窗口会小一半。
    """
    try:
        import ctypes
        from ctypes import wintypes
        rect = wintypes.RECT()
        # SPI_GETWORKAREA = 0x0030，返回的是工作区（去掉任务栏后的桌面）
        if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0):
            w, h = rect.right - rect.left, rect.bottom - rect.top
            if w > 0 and h > 0:
                return w, h
    except Exception:
        pass
    try:
        import ctypes
        user32 = ctypes.windll.user32
        w, h = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
        if w > 0 and h > 0:
            return w, h
    except Exception:
        pass
    return 1920, 1080


def open_app_window(url: str, browser: str) -> bool:
    """用 --app 模式打开无边框独立窗口。失败返回 False，由调用方退回默认浏览器。"""
    sw, sh = _screen_size()
    w = max(900, min(1180, sw - 160))
    h = max(620, min(820, sh - 180))
    x = max(0, (sw - w) // 2)
    y = max(0, (sh - h) // 3)           # 稍微偏上，比正中更顺眼
    try:
        subprocess.Popen(
            [browser,
             "--app=" + url,
             "--window-size=%d,%d" % (w, h),
             "--window-position=%d,%d" % (x, y),
             "--no-first-run",
             "--no-default-browser-check",
             "--disable-features=Translate"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False


def open_ui(url: str, app_mode: bool = True) -> str:
    """
    打开界面，返回实际用掉的模式："app"（独立窗口）/ "tab"（浏览器标签）/ "none"。
    app 模式不可用时自动退回系统默认浏览器，绝不因为找不到 Edge 就打不开。
    """
    if app_mode and os.name == "nt":
        found = find_app_browser()
        if found and open_app_window(url, found):
            return "app"
    try:
        import webbrowser
        if webbrowser.open(url):
            return "tab"
    except Exception:
        pass
    return "none"


def run_gui(port: int = 0, open_browser: bool = True, out_hint: str | None = None,
            app_mode: bool = True) -> int:
    """启动本地网页控制台。只在 127.0.0.1 上监听，并带一次性访问令牌。"""
    import http.server
    import io as _io
    import secrets
    import tempfile
    import threading
    import urllib.parse
    import webbrowser
    import zipfile

    token = secrets.token_urlsafe(12)
    session = Path(tempfile.mkdtemp(prefix="ncm2mp3_ui_"))
    up_dir = session / "in"
    up_dir.mkdir()
    # 兜底目录：用户指定的输出目录不可写时，退回这里
    fallback_dir = session / "out"
    fallback_dir.mkdir()
    default_out = Path(out_hint) if out_hint else default_output_dir()

    def resolve_out(raw: str):
        """解析输出目录，返回 (目录, 是否退回了临时目录)。"""
        p = (raw or "").strip().strip('"').strip("'")
        cand = Path(p) if p else default_out
        try:
            cand.mkdir(parents=True, exist_ok=True)
            probe = cand / f".ncm2mp3_probe_{os.getpid()}"
            probe.write_bytes(b"")
            probe.unlink(missing_ok=True)
            return cand, False
        except OSError:
            return fallback_dir, True
    # 直接关窗口时进程被强杀，finally 不会执行，这里顺手清理过期会话目录
    try:
        now = time.time()
        for old in Path(tempfile.gettempdir()).glob("ncm2mp3_ui_*"):
            if old.is_dir() and now - old.stat().st_mtime > 3600:
                shutil.rmtree(old, ignore_errors=True)
    except OSError:
        pass
    converted: list[Path] = []
    lock = threading.Lock()
    ffmpeg = shutil.which("ffmpeg")
    # 拖进队列的文件会先上传一次并缓存下来（顺便读出封面/时长/歌名），
    # 之后点「开始导出」直接用这个缓存，不用把文件再传一遍。
    uploads: dict[str, tuple[Path, str]] = {}      # id -> (缓存路径, 原始文件名)
    # 界面状态：
    #   busy   —— 当前正在转换的任务数（有任务在跑就先别退出）
    #   bye    —— 收到「窗口已关闭」信标的时间，0 表示没有待处理的退出
    #   loaded —— 界面是否至少成功加载过一次（没加载过就退出可能是误判）
    #   picker —— 正在跑的那个「选择文件夹」对话框子进程，用于「强制关闭」
    state = {"busy": 0, "bye": 0.0, "loaded": False, "picker": None}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "ncm2mp3"

        def log_message(self, *a):        # 静音访问日志
            pass

        # ---------- 基础工具 ----------
        def _send(self, code, body: bytes, ctype="text/plain; charset=utf-8", extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            buf = bytearray()
            while len(buf) < n:
                chunk = self.rfile.read(min(1 << 20, n - len(buf)))
                if not chunk:
                    break
                buf += chunk
            return bytes(buf)

        def _json_body(self) -> dict:
            try:
                return json.loads(self._body() or b"{}")
            except Exception:
                return {}

        def _parts(self):
            parsed = urllib.parse.urlparse(self.path)
            seg = parsed.path.strip("/").split("/", 1)
            tok = seg[0] if seg else ""
            rest = seg[1] if len(seg) > 1 else ""
            return tok, rest, urllib.parse.parse_qs(parsed.query)

        def _guard(self):
            """校验令牌；不通过时已回包，调用方直接 return。"""
            tok, _, _ = self._parts()
            if not secrets.compare_digest(tok, token):
                self._json({"ok": False, "msg": "访问令牌无效"}, 403)
                return False
            return True

        # ---------- 路由 ----------
        def do_GET(self):
            if not self._guard():
                return
            _, rest, q = self._parts()
            if rest in ("", "index.html"):
                with lock:
                    state["loaded"] = True
                    state["bye"] = 0.0        # 页面重新加载 = 用户还在用，撤销待退出
                page = (_GUI_PAGE
                        .replace("__OUTDIR__", html_attr(default_out))
                        .replace("__TOKEN__", token))
                self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            elif rest == "api/zip":
                self._do_zip()
            elif rest == "api/download":
                self._do_download(q)
            else:
                self._json({"ok": False, "msg": "未知接口"}, 404)

        def do_POST(self):
            if not self._guard():
                return
            _, rest, q = self._parts()
            if rest == "api/convert":
                self._do_convert_upload(q)
            elif rest == "api/info":
                self._do_info(q)
            elif rest == "api/drop":
                self._do_drop()
            elif rest == "api/scan":
                self._do_scan()
            elif rest == "api/convert-path":
                self._do_convert_path()
            elif rest == "api/reveal":
                self._do_reveal()
            elif rest == "api/quit":
                self._do_quit()
            elif rest == "api/bye":
                self._do_bye()
            elif rest == "api/pick":
                self._do_pick()
            elif rest == "api/pick-cancel":
                self._do_pick_cancel()
            else:
                self._json({"ok": False, "msg": "未知接口"}, 404)

        # ---------- 拖入队列：缓存文件并读出元信息 ----------
        def _do_info(self, q):
            raw_name = (q.get("name") or ["upload.ncm"])[0]
            data = self._body()
            if not data:
                self._json({"ok": False, "msg": "收到空文件"})
                return
            fid = uuid.uuid4().hex[:16]
            src = up_dir / (fid + ".ncm")
            try:
                src.write_bytes(data)
            except OSError as e:
                self._json({"ok": False, "msg": f"写缓存失败：{e}"})
                return
            try:
                info = probe_ncm(src)
            except NcmError as e:
                src.unlink(missing_ok=True)
                self._json({"ok": False, "msg": str(e)})
                return
            except Exception as e:
                src.unlink(missing_ok=True)
                self._json({"ok": False, "msg": f"{type(e).__name__}: {e}"})
                return
            with lock:
                uploads[fid] = (src, raw_name)
            self._json({"ok": True, "id": fid, "src": raw_name, "info": info})

        # ---------- 从队列里移除文件（单个或批量） ----------
        def _do_drop(self):
            req = self._json_body()
            ids = req.get("ids")
            if not isinstance(ids, list):
                ids = [req.get("id")] if req.get("id") else []
            killed = 0
            for fid in ids:
                with lock:
                    got = uploads.pop(str(fid), None)
                if got:
                    try:
                        got[0].unlink(missing_ok=True)
                        killed += 1
                    except OSError:
                        pass
            self._json({"ok": True, "n": killed})

        # ---------- 上传转换 ----------
        def _do_convert_upload(self, q):
            fid = (q.get("id") or [""])[0]
            raw_name = (q.get("name") or ["upload.ncm"])[0]
            target, is_fallback = resolve_out((q.get("out") or [""])[0])

            if fid:
                # 队列里拖进来的文件：直接用上传时缓存的那份，不重复传输，
                # 而且转换只读不删，所以失败了换个选项还能再试。
                with lock:
                    got = uploads.get(fid)
                if got is None:
                    self._json({"ok": False, "msg": "这个文件的缓存已失效，请重新拖进来"})
                    return
                src, raw_name = got
            else:
                # 兼容旧调用：文件直接放在请求体里，转完就删
                data = self._body()
                if not data:
                    self._json({"ok": False, "msg": "收到空文件"})
                    return
                src = up_dir / (uuid.uuid4().hex[:16] + ".ncm")
                src.write_bytes(data)
                try:
                    ok, msg, out_path = convert_one(
                        str(src), str(target),
                        (q.get("cover") or ["0"])[0] == "1",
                        (q.get("to_mp3") or ["0"])[0] == "1",
                        ffmpeg)
                finally:
                    src.unlink(missing_ok=True)

                if ok and out_path:
                    with lock:
                        converted.append(out_path)
                    self._json({"ok": True, "msg": msg, "out": out_path.name,
                                "dir": str(target), "fallback": is_fallback,
                                "fmt": out_path.suffix.lstrip("."),
                                "mb": round(out_path.stat().st_size / 1048576, 1)})
                else:
                    self._json({"ok": False, "msg": msg})
                return

            with lock:
                state["busy"] += 1
            try:
                ok, msg, out_path = convert_one(
                    str(src), str(target),
                    (q.get("cover") or ["0"])[0] == "1",
                    (q.get("to_mp3") or ["0"])[0] == "1",
                    ffmpeg)
            finally:
                with lock:
                    state["busy"] -= 1

            if ok and out_path:
                with lock:
                    converted.append(out_path)
                self._json({"ok": True, "msg": msg, "out": out_path.name,
                            "dir": str(target), "fallback": is_fallback,
                            "fmt": out_path.suffix.lstrip("."),
                            "mb": round(out_path.stat().st_size / 1048576, 1)})
            else:
                self._json({"ok": False, "msg": msg})

        # ---------- 目录模式 ----------
        def _do_scan(self):
            req = self._json_body()
            p = str(req.get("path", "")).strip().strip('"').strip("'")
            if not p:
                self._json({"ok": False, "msg": "请填写目录路径"})
                return
            if not Path(p).exists():
                self._json({"ok": False, "msg": f"路径不存在：{p}"})
                return
            self._json({"ok": True, "files": collect_inputs([p])})

        def _do_convert_path(self):
            req = self._json_body()
            src = str(req.get("path", "")).strip().strip('"').strip("'")
            dst = str(req.get("out", "")).strip().strip('"').strip("'") or None
            if not src:
                self._json({"ok": False, "msg": "请填写目录路径"})
                return
            files = collect_inputs([src])
            if not files:
                self._json({"ok": False, "msg": "这个目录里没找到 .ncm 文件"})
                return
            results = []
            okn = 0
            with lock:
                state["busy"] += 1
            try:
                for f in files:
                    ok, msg, out_path = convert_one(f, dst, bool(req.get("cover")),
                                                    bool(req.get("to_mp3")), ffmpeg)
                    okn += ok
                    results.append({"name": Path(f).name, "ok": bool(ok), "note": msg})
                    if ok and out_path:
                        with lock:
                            converted.append(out_path)
            finally:
                with lock:
                    state["busy"] -= 1
            self._json({"ok": True, "results": results,
                        "msg": f"完成：成功 {okn} 个，失败 {len(files) - okn} 个"})

        # ---------- 系统对话框 / 打开目录 / 退出 ----------
        def _do_pick(self):
            """
            调起系统「选择文件夹」对话框。

            这里有两个坑必须一起绕开：

            1) **对话框会被压在窗口后面（之前那个 bug）**
               对话框是本程序的一个【后台子进程】创建的，子进程不是前台进程。
               Windows 有个前台锁：不是前台进程就别想把窗口抢到最前面 ——
               所以 `ShowDialog()` 不指定 owner 时，对话框会在后面悄悄打开，
               顶多在任务栏闪一下，用户看到的就是"按钮变成选择中，但没弹窗"。
               解法：先建一个 1x1 的 **TopMost** owner 窗口，再把对话框以它为 owner
               弹出来。Windows 保证 owned window 永远压在自己的 owner 之上，
               owner 又是 TopMost —— 于是对话框必然显示在最上层。实测有效。

            2) **中文路径乱码**
               重定向 stdout 时 PowerShell 按控制台代码页输出，
               中文目录名会解码失败（UnicodeDecodeError）。所以路径不直接打印，
               改成 UTF-8 的 Base64 再输出 —— 纯 ASCII，任何代码页都不会坏。

            另外把当前输入框里的目录作为初始位置，省得每次从头点。
            """
            path = ""
            if os.name == "nt":
                req = self._json_body()

                # 同一时刻只允许开一个：两个 PowerShell 对话框叠在一起，用户点哪个都晕
                with lock:
                    if state.get("picker") is not None:
                        self._json({"ok": False, "busy": True,
                                    "msg": "已经有选择窗口开着了，先把它关掉再点"})
                        return

                seed = str(req.get("path", "") or "").strip()
                # 对话框标题按用途区分。这段会拼进 PowerShell 的单引号字符串里，
                # 所以把能"跳出"单引号或做插值的字符统统去掉（正常标题里也用不到）。
                desc = str(req.get("desc", "") or "")
                desc = re.sub(r"['\"`$\r\n;]", "", desc).strip()[:40] or "选择文件夹"
                seed_ps = (
                    "if (Test-Path -LiteralPath $env:NCM_PICK_SEED -PathType Container)"
                    " { $d.SelectedPath = $env:NCM_PICK_SEED };"
                    if seed else ""
                )
                ps = (
                    "$ErrorActionPreference = 'Stop';"
                    "Add-Type -AssemblyName System.Windows.Forms;"
                    # --- 1x1 的隐形 owner，TopMost 保证对话框在最前线 ---
                    "$o = New-Object System.Windows.Forms.Form;"
                    "$o.Text = '选择保存位置';"
                    "$o.FormBorderStyle = 'None';"
                    "$o.ShowInTaskbar = $false;"
                    "$o.StartPosition = 'CenterScreen';"
                    "$o.Size = New-Object System.Drawing.Size(1,1);"
                    "$o.TopMost = $true;"
                    "$o.Show();"
                    "$d = New-Object System.Windows.Forms.FolderBrowserDialog;"
                    "$d.Description = '" + desc + "';"
                    "$d.ShowNewFolderButton = $true;"
                    + seed_ps +
                    "try {"
                    "  if ($d.ShowDialog($o) -eq [System.Windows.Forms.DialogResult]::OK)"
                    "  { [Convert]::ToBase64String("
                    "      [System.Text.Encoding]::UTF8.GetBytes($d.SelectedPath)) | Write-Output }"
                    "} finally { $o.Close(); $o.Dispose() }"
                )
                env = dict(os.environ)
                if seed:
                    env["NCM_PICK_SEED"] = seed
                try:
                    proc = subprocess.Popen(
                        ["powershell", "-NoProfile", "-STA", "-Command", ps],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, encoding="ascii", errors="replace",
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        env=env,
                    )
                    with lock:
                        state["picker"] = proc
                    try:
                        # 对话框可能一直开着，这里给足时间；期间用户可点「强制关闭」
                        out, _err = proc.communicate(timeout=1800)
                    finally:
                        with lock:
                            state["picker"] = None
                    line = (out or "").strip().splitlines()
                    if line:
                        raw = line[-1].strip()
                        try:                       # Base64 → UTF-8，失败就退回原文
                            path = base64.b64decode(raw).decode("utf-8").strip()
                        except Exception:                                  # noqa: BLE001
                            path = raw
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                    except Exception:                                  # noqa: BLE001
                        pass
                    self._json({"ok": False, "msg": "等待选择太久了，请重新点一次"})
                    return
                except Exception as e:                                 # noqa: BLE001
                    self._json({"ok": False, "msg": f"调用系统对话框失败：{e}"})
                    return
            if path:
                self._json({"ok": True, "path": path})
            else:
                self._json({"ok": False, "msg": "没有选择目录"})

        def _do_pick_cancel(self):
            """用户点了「没看到窗口？强制关闭」——把那个卡住的对话框子进程干掉。"""
            with lock:
                proc = state.get("picker")
            if proc is None:
                self._json({"ok": True, "msg": "当前没有正在等待的选择框"})
                return
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=15,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except Exception:                                          # noqa: BLE001
                try:
                    proc.kill()
                except Exception:                                      # noqa: BLE001
                    pass
            self._json({"ok": True, "msg": "已关闭"})

        def _do_reveal(self):
            req = self._json_body()
            target, is_fallback = resolve_out(str(req.get("path", "")))
            try:
                if os.name == "nt":
                    os.startfile(str(target))            # noqa: S606
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", str(target)])
                else:
                    subprocess.Popen(["xdg-open", str(target)])
                self._json({"ok": True, "dir": str(target), "fallback": is_fallback})
            except Exception as e:
                self._json({"ok": False, "msg": f"打不开目录：{e}", "dir": str(target)})

        def _do_quit(self):
            self._json({"ok": True, "msg": "已退出"})

            def bye():
                shutil.rmtree(session, ignore_errors=True)
                os._exit(0)                              # 窗口已关，直接退干净

            threading.Timer(0.35, bye).start()

        def _do_bye(self):
            """
            窗口正在关闭。这里只做标记，真正的退出交给后台守候线程判断 ——
            因为「刷新页面」也会触发 pagehide，得留一点时间让新页面加载来撤销。
            """
            with lock:
                state["bye"] = time.time()
            self._json({"ok": True})

        # ---------- 下载 ----------
        def _do_zip(self):
            with lock:
                items = list(converted)
            if not items:
                self._json({"ok": False, "msg": "还没有转换完成的文件"}, 400)
                return
            buf = _io.BytesIO()
            used: set[str] = set()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for p in items:
                    if not p.exists():
                        continue
                    arc, i = p.name, 2
                    while arc in used:
                        arc = f"{p.stem} ({i}){p.suffix}"
                        i += 1
                    used.add(arc)
                    z.write(p, arc)
            self._send(200, buf.getvalue(), "application/zip",
                       {"Content-Disposition": 'attachment; filename="ncm-converted.zip"'})

        def _do_download(self, q):
            try:
                idx = int((q.get("i") or ["0"])[0])
            except ValueError:
                idx = 0
            with lock:
                if not (0 <= idx < len(converted)):
                    self._json({"ok": False, "msg": "文件不存在"}, 404)
                    return
                p = converted[idx]
            if not p.exists():
                self._json({"ok": False, "msg": "文件已被清理"}, 404)
                return
            self._send(200, p.read_bytes(), "application/octet-stream",
                       {"Content-Disposition":
                        "attachment; filename*=UTF-8''" + urllib.parse.quote(p.name)})

    try:
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        print(f"启动失败：{e}")
        return 1

    url = f"http://127.0.0.1:{httpd.server_address[1]}/{token}/"
    print("=" * 62)
    print("  NCM 转换器 · 本地网页控制台")
    print()
    print(f"  地址：{url}")
    print("  关掉界面窗口就会退出程序（命令行下也可以按 Ctrl+C）")
    print("=" * 62)
    # 输出被重定向到管道/文件时是块缓冲的，主动刷一下，
    # 否则调用方（比如别的脚本）会一直读不到地址。
    try:
        sys.stdout.flush()
    except Exception:
        pass

    if IS_FROZEN:
        # 打包成 exe 后没有控制台窗口。万一界面没自动弹出来（或你不小心关了），
        # 就照这个文件里的地址手动打开。
        try:
            (Path(tempfile.gettempdir()) / "ncm2mp3_界面地址.txt").write_text(
                url + "\n", encoding="utf-8")
        except OSError:
            pass

    def watch_close():
        """
        关窗口 = 退出程序。

        因为应用窗口没有地址栏，关掉以后用户就找不回界面了，留着这个后台进程
        没意义。刷新页面同样会触发 pagehide，但刷新会立刻重新加载页面，而
        do_GET 里会把 state["bye"] 清掉 —— 所以这里等 5 秒确认没人撤销才退。
        有任务在跑就先顺延，别把正转换到一半的活儿掐死。
        """
        while True:
            time.sleep(0.4)
            with lock:
                bye_at, busy_now, loaded = state["bye"], state["busy"], state["loaded"]
            if not bye_at or not loaded:
                continue
            if busy_now:
                with lock:
                    state["bye"] = time.time()          # 还在转，重新计时
                continue
            if time.time() - bye_at >= 5.0:
                shutil.rmtree(session, ignore_errors=True)
                os._exit(0)

    if open_browser:
        mode = ["?"]

        def _launch():
            mode[0] = open_ui(url, app_mode)
            print("  界面已打开：" + {
                "app": "独立窗口（无地址栏）",
                "tab": "浏览器标签（没找到 Edge/Chrome）",
                "none": "自动打开失败，请手动访问上面的地址",
            }.get(mode[0], mode[0]))
            try:
                sys.stdout.flush()
            except Exception:
                pass

        threading.Timer(0.4, _launch).start()
        threading.Thread(target=watch_close, daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出。")
    finally:
        httpd.server_close()
        shutil.rmtree(session, ignore_errors=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="网易云音乐 .ncm 文件解密 / 转码工具（零依赖）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="例：python ncm2mp3.py D:\\Music\\ncm --cover --to-mp3",
    )
    ap.add_argument("paths", nargs="*",
                    help="要转换的 .ncm 文件或目录（目录会递归查找）。不填则打开网页控制台")
    ap.add_argument("-o", "--out", default=None, help="输出目录（默认与原文件同目录）")
    ap.add_argument("-j", "--jobs", type=int, default=1, help="并行进程数（默认 1）")
    ap.add_argument("--cover", action="store_true", help="同时导出专辑封面为 jpg")
    ap.add_argument("--to-mp3", action="store_true", help="源是 flac 等格式时，用 ffmpeg 转成 mp3")
    ap.add_argument("--gui", action="store_true", help="打开本地网页控制台（不填路径时默认打开）")
    ap.add_argument("--port", type=int, default=0, help="网页控制台端口，默认自动分配")
    ap.add_argument("--no-browser", action="store_true", help="打开控制台时不自动拉起浏览器")
    ap.add_argument("--no-app", action="store_true",
                    help="用普通浏览器标签打开界面，不用无地址栏的独立窗口")
    ap.add_argument("--out-dir", default=None, help="网页控制台里「导出到」的默认目录")
    ap.add_argument("--here", action="store_true", help="命令行模式下转换当前目录（等价于传入 . 号）")
    args = ap.parse_args(argv)

    if args.gui or (not args.paths and not args.here):
        return run_gui(args.port, not args.no_browser, args.out_dir,
                       app_mode=not args.no_app)

    targets = args.paths or ["."]

    files = collect_inputs(targets)
    if not files:
        print("没找到任何 .ncm 文件。")
        return 1

    maybe_ffmpeg = shutil.which("ffmpeg")
    if args.to_mp3 and not maybe_ffmpeg:
        print("[提示] 未检测到 ffmpeg，--to-mp3 会失败。可先安装：winget install Gyan.FFmpeg")

    print(f"共 {len(files)} 个文件，开始转换（进程数 {args.jobs}）...\n")
    ok = 0
    fail = 0

    if args.jobs > 1 and len(files) > 1:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            futs = [pool.submit(convert_one, f, args.out, args.cover, args.to_mp3, maybe_ffmpeg)
                    for f in files]
            for fut in as_completed(futs):
                success, msg, _ = fut.result()
                print(msg)
                ok += success
                fail += (not success)
    else:
        for f in files:
            success, msg, _ = convert_one(f, args.out, args.cover, args.to_mp3, maybe_ffmpeg)
            print(msg)
            ok += success
            fail += (not success)

    print(f"\n完成：成功 {ok}，失败/跳过 {fail}")
    return 0 if fail == 0 else 2


if __name__ == "__main__":
    _ensure_std_streams()      # 打包成无控制台的 exe 时，stdout 是 None，print 会崩
    import multiprocessing
    multiprocessing.freeze_support()   # 为将来打包 exe 预留：多进程模式在 exe 里必需
    sys.exit(main())

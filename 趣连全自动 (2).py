#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
趣连（com.kuaixiang.qulian）全自动节点获取脚本
适配环境：Android Termux / Linux / Windows / macOS
核心特性：
  1. 支持 pytesseract（Termux 原生推荐）及 ddddocr 双引擎自适应。
  2. 针对 5 位动图验证码做「多帧提取 + 边缘补白 + 二值化去噪 + 多帧投票」，高成功率。
  3. 自动生成虚拟设备与账号，自动识别验证码并注册。
  4. 自动领取新用户福利。
  5. 多线程并发拉取全量节点，自动解析 VLESS Reality 与 Trojan 协议并导出。

Termux 运行前准备：
  pkg install tesseract python
  pip install pytesseract pycryptodome pillow
"""

import base64
import hashlib
import io
import json
import os
import random
import string
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# 保证各平台终端中文正常打印
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ================================================================ OCR 引擎自适应导入
USE_OCR_ENGINE = None
_DDDD_OCR_INSTANCE = None

try:
    import pytesseract
    USE_OCR_ENGINE = "tesseract"
except ImportError:
    try:
        import ddddocr
        USE_OCR_ENGINE = "ddddocr"
    except ImportError:
        pass

from PIL import Image, ImageSequence, ImageOps
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad

# ================================================================ 核心配置
BASE_URLS = [
    "https://api2.zestlink.com:48574/vpn/api",
    "https://api.zestlink.com/vpn/api",
    "https://47.86.62.170/vpn/api",
]
VERSION = "170"
SYSTEM_TYPE = "Android"
DEVICE_MODEL = "XT2201_2"
UA = f"Mozilla/5.0 (Linux; Android 14; {DEVICE_MODEL}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
AES_IV = b"9583012938476028"
_RSA_XOR_KEY = "qLv9aK2vP0x#"

_RSA_PRIV_B64 = (
    "PAU/egU8ezQRdDltMysdSAkgWzFpR0hhMB0zfyAKYTURXT1UFis8XSAsdzcRXz9hMAEef1YuViMDQAwT"
    "JXkXcgx/fC4bew13RxkyXyQKU09heFNxKXowbFgAezJjUjtwJSU9FhYbVhMqfE5vRCIkAVAFSgViWQkb"
    "JSoafjMAAw8cSRtlPBw/ThAsBAYcZTJ1BiASYwoRQB42ehdqQjonTisvQCcWcy0aNypCdQs+QT9odA9F"
    "SBUEWylzCyUfRDBURXwbcwgGWQIdQTlsOHsmckp5eiwbexNKKQsAayAsfzQRcT1gFhUzeBJ/SiEUdi8V"
    "GBU/di8NaiQkdEEXBHU8Xgkaf0Q1cSxoPx43WlIyfQMbXUxaQzYwXwopdV0TABB7KAMwf1NyRgcyQVMb"
    "PQ8/U0opBwEgVAsMBgEcWxEhBD85ZEgaQD8/TwwzWRgyfkB1KWNGag4YWzc7ZwFHWjU0UxVyXTk7fypF"
    "AztBDVMiXR8fXTFzOwtPATgkRxQgWBx5OAE8XFkNZB0+d05RIyldfCARAjUBYTwSOzgbWxUdWRw4RA90"
    "An4PXycgCgQWXlNzQQQ+YxAoABQxQRR5Fxs7aipyZhVmdxBnHgMsdTAERRM2YAJpP3QzCA4dWjBlGwFG"
    "JCgZWFE+WSQjWRdBMCczeFEYeQM1SE1mBAUbUCcNaxMbaTtsFwQRSBMkXEZmcg4IHT4jXk4BATQEQzcW"
    "RA4dahA6BF06alcbBhgbdDR7QE8fWCxMISsMYS0ffjw/ZSJqCHo1XgY8eDQRfDF5An4vcVYuaE84AFNk"
    "AjwVQSgtQAAjZyxtCz0faTQISh1lYAwVBAUETyMaXRkIVhtJRS0FQDR6VR9/ajZhCCc3Vih4ZDBpYS5F"
    "Wig3WyAtc0cfBRNgIAkAC1MsYiM5Ux1aNTw8TAQSY1kjRzB5PAhdClE6eRFgeR5ZFgMcUQIDBRkiASli"
    "Nn8PTU4lCkJpQhRmRzsfQC55QBs2ShRwBT4/Ty4TVTccek9aJgQFejAPcQIDVQwSKTkcSzIPYkQAaipT"
    "PHkzeFY6dwA3Y0oMNz5DUTMzeywodxkMBh9GTgMDXRIidBxJNH4XDwQ7ZQEAZk1iQCIeDyYmXkEdXCBn"
    "MwABfy0RY0s="
)
_RSA_PUB_B64 = (
    "PAUxXywKAjETYwlkIgUUCiUadzQRYS1iMHgxdyAPcTQ5YTNhFh01XikABRgVAgJuQjYdYA4MAycWQQ1v"
    "GzUyYTAbWy8HWE9HBHsHDjgxWSYiCE16CDYAY1gHREAqdTFHMCM9XBBgQSQRVzBLRjVZYQASYjQHaTZS"
    "GiIndSUtQgMEcjlnAjZOTCZ6QDVnUUxWHX4jAStgBT84BCkaQzs3dg0mXkAFaUBaMg1AbxAFZUFpRixN"
    "RhoUbSspATMCd0F6IiQSYwp5UEM/VjxqMgtBbSkaezIRYTlh"
)

_PRINT_LOCK = threading.Lock()

# 智能判断保存路径
if os.path.exists("/storage/emulated/0/Download"):
    OUT_DIR = "/storage/emulated/0/Download/"
else:
    OUT_DIR = os.path.join(os.path.expanduser("~"), "Downloads")

OUTPUT_FILE = "趣连.txt"
CONCURRENCY = 8

# 全局缓存
_PRIV_KEY = None
_PUB_KEY = None

# ================================================================ 密码学工具函数
def _xor_decode(b64: str, key: str) -> str:
    raw = base64.b64decode(b64).decode("latin1")
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(raw))

def _init_modules():
    global _PRIV_KEY, _PUB_KEY, _DDDD_OCR_INSTANCE
    if _PRIV_KEY is None:
        priv_der = base64.b64decode(_xor_decode(_RSA_PRIV_B64, _RSA_XOR_KEY))
        pub_der = base64.b64decode(_xor_decode(_RSA_PUB_B64, _RSA_XOR_KEY))
        _PRIV_KEY = RSA.import_key(priv_der)
        _PUB_KEY = RSA.import_key(pub_der)
    if USE_OCR_ENGINE == "ddddocr" and _DDDD_OCR_INSTANCE is None:
        import ddddocr
        _DDDD_OCR_INSTANCE = ddddocr.DdddOcr(show_ad=False)

def aes_encrypt(plaintext: bytes, key: bytes) -> str:
    cipher = AES.new(key[:16], AES.MODE_CBC, AES_IV)
    return base64.b64encode(cipher.encrypt(pad(plaintext, 16))).decode()

def aes_decrypt(b64: str, key: bytes) -> str:
    cipher = AES.new(key[:16], AES.MODE_CBC, AES_IV)
    return unpad(cipher.decrypt(base64.b64decode(b64)), 16).decode("utf-8")

def rsa_encrypt_pkcs1(plaintext: bytes) -> str:
    return base64.b64encode(PKCS1_v1_5.new(_PUB_KEY).encrypt(plaintext)).decode()

def rsa_decrypt_pkcs1(b64: str) -> bytes:
    return PKCS1_v1_5.new(_PRIV_KEY).decrypt(base64.b64decode(b64), None) or b""

def rsa_sign_sha256(message: str) -> str:
    k = _PRIV_KEY.size_in_bytes()
    digest = hashlib.sha256(message.encode()).digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    t = digest_info + digest
    em = b"\x00\x01" + b"\xff" * (k - 3 - len(t)) + b"\x00" + t
    sig = pow(int.from_bytes(em, "big"), _PRIV_KEY.d, _PRIV_KEY.n)
    return base64.b64encode(sig.to_bytes(k, "big")).decode()

def canon_json(v) -> str:
    if v is None: return ""
    if isinstance(v, list): return "[" + ",".join(canon_json(x) or "null" for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(k for k in v if v[k] is not None)
        return "{" + ",".join(json.dumps(k, ensure_ascii=False, separators=(",", ":")) + ":" + canon_json(v[k]) for k in keys) + "}"
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))

def _nonce(length=16):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def api_request(path: str, method: str, data: dict, token: str = "", imei: str = "", extra_headers: dict = None, timeout: int = 12):
    last_err = None
    for base in BASE_URLS:
        try:
            ts = str(int(time.time() * 1000))
            nonce = _nonce(16)
            aes_key = _nonce(16)
            plaintext = canon_json(data)
            body = {
                "encryptData": aes_encrypt(plaintext.encode("utf-8"), aes_key.encode()),
                "encryptKey": rsa_encrypt_pkcs1(aes_key.encode()),
            }
            sign_path = "/vpn/api" + path
            signature = rsa_sign_sha256(f"{ts}\n{nonce}\n{sign_path}\n{plaintext}")
            trace = aes_encrypt(f"{ts}|{nonce}|{path}|{int(time.time())}".encode(), nonce.encode())
            
            headers = {
                "Accept": "application/json", "Content-Type": "application/json",
                "version": VERSION, "System-Type": SYSTEM_TYPE, "Device": imei or "",
                "User-Agent": UA, "X-Req-Timestamp": ts, "X-Req-Nonce": nonce,
                "X-Req-Signature": signature, "X-Client-Trace": trace, "X-Client-Debug": "0",
            }
            if token:
                headers["VPN-USER-TOKEN"] = token
            if extra_headers:
                headers.update(extra_headers)
                
            if method == "GET":
                qs = f"encryptData={urllib.parse.quote(body['encryptData'], safe='')}&encryptKey={urllib.parse.quote(body['encryptKey'], safe='')}"
                url = base + path + ("&" if "?" in path else "?") + qs
                req = urllib.request.Request(url, headers=headers, method="GET")
            else:
                req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers=headers, method=method)
                
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
                
            if isinstance(raw, dict) and raw.get("encrypted") and raw.get("data"):
                key = rsa_decrypt_pkcs1(raw["encrypted"])
                return json.loads(aes_decrypt(raw["data"], key))
            return raw
        except Exception as ex:
            last_err = ex
    raise RuntimeError(f"API 请求失败 ({path}): {last_err}")

# ================================================================ 验证码获取与识别 (支持 Pytesseract / DdddOcr)
def get_captcha_image(imei: str) -> tuple[str, bytes]:
    """获取验证码 UUID 与图片字节"""
    for base in BASE_URLS:
        try:
            url = f"{base}/captcha/image"
            req = urllib.request.Request(url, headers={
                "Device": imei,
                "version": VERSION,
                "User-Agent": UA,
            })
            with urllib.request.urlopen(req, timeout=8) as resp:
                headers = dict(resp.getheaders())
                uuid = headers.get("X-Captcha-Uuid") or headers.get("x-captcha-uuid")
                img_bytes = resp.read()
                if uuid and img_bytes and img_bytes[:4] in (b"GIF8", b"\x89PNG"):
                    return uuid, img_bytes
        except Exception:
            continue
    raise RuntimeError("获取验证码图片失败，所有端点均不可达或受频控限制。")

def solve_animated_captcha(img_bytes: bytes) -> str:
    """多帧提取 + 边缘补白 + 多数投票识别动图验证码"""
    if not USE_OCR_ENGINE:
        raise RuntimeError("未检测到可用的 OCR 引擎！请在 Termux 安装: pkg install tesseract; pip install pytesseract")

    try:
        im = Image.open(io.BytesIO(img_bytes))
        candidates = []
        
        for frame in ImageSequence.Iterator(im):
            rgb = frame.convert("RGB")
            bg_color = rgb.getpixel((0, 0))
            # 扩展 15px 外边距，防止边缘字母贴边被切
            padded = ImageOps.expand(rgb, border=15, fill=bg_color)
            
            code = ""
            if USE_OCR_ENGINE == "tesseract":
                # 针对 Tesseract 调优：灰度化 + 阈值二值化（有效滤除噪点与浅色划线）
                gray = padded.convert("L")
                bin_img = gray.point(lambda p: 255 if p > 140 else 0)
                tess_cfg = (
                    r"--psm 7 "
                    r"-c tessedit_char_whitelist=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                )
                raw_text = pytesseract.image_to_string(bin_img, config=tess_cfg)
                code = "".join(ch for ch in raw_text if ch.isalnum()).strip().lower()
                
            elif USE_OCR_ENGINE == "ddddocr":
                buf = io.BytesIO()
                padded.save(buf, format="PNG")
                code = _DDDD_OCR_INSTANCE.classification(buf.getvalue()).strip().lower()
                
            # 仅采纳长度为 5 且纯字母数字的结果
            if len(code) == 5 and code.isalnum():
                candidates.append(code)
                
        if candidates:
            # 多数投票取最高频结果
            return Counter(candidates).most_common(1)[0][0]
    except Exception:
        pass
    return ""

def auto_register_with_captcha(email: str, password: str, imei: str, max_retries: int = 6) -> str:
    """全自动重试注册（带验证码自刷新机制）"""
    for attempt in range(1, max_retries + 1):
        try:
            uuid, img_bytes = get_captcha_image(imei)
            code = solve_animated_captcha(img_bytes)
            if not code or len(code) != 5:
                time.sleep(0.5)
                continue
                
            extra_headers = {
                "X-Sign-Up": "1",
                "X-Captcha-Uuid": uuid,
                "X-Captcha-Code": code,
            }
            
            r = api_request(
                "/user/signup", "POST",
                {"name": email, "password": password},
                imei=imei, extra_headers=extra_headers
            )
            if isinstance(r, dict):
                if r.get("token"):
                    print(f"      [第 {attempt} 次识别] 验证码: '{code}' -> 注册成功!")
                    return r["token"]
                elif r.get("code") == 180:
                    print(f"      [第 {attempt} 次识别] 验证码 '{code}' 不匹配，刷新重试...")
                    time.sleep(0.8)
                    continue
            print(f"      [第 {attempt} 次尝试] 异常响应: {r}")
        except Exception as ex:
            print(f"      [第 {attempt} 次尝试] 错误: {ex}")
            time.sleep(1)
            
    raise RuntimeError(f"连续 {max_retries} 次验证码识别均未能成功，请检查 OCR 环境或稍后重试。")

# ================================================================ 业务解析逻辑
def gen_email():
    local = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    return f"{local}@zestlink.example.com"

def gen_password():
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(12))

def gen_imei():
    return "".join(random.choice("0123456789ABCDEF") for _ in range(32))

def parse_leaf_trojan(cfg: str):
    proto = host = port = password = sni = None
    for idx, line in enumerate((cfg or "").splitlines()):
        line = line.strip()
        if line.startswith("Proxy =") and "direct" not in line.lower():
            spec = line[len("Proxy ="):]
            for nxt in (cfg or "").splitlines()[idx + 1:]:
                nxt = nxt.strip()
                if nxt.startswith("["): break
                spec += nxt
            parts = [p.strip() for p in spec.split(",")]
            proto, host, port = (parts + [None]*3)[:3]
            for p in parts[3:]:
                pl = p.lower()
                if pl.startswith("password="): password = p.split("=", 1)[1]
                elif pl.startswith("sni="): sni = p.split("=", 1)[1]
            break
    return proto, host, port, password, sni

def parse_vless_config(cfg: str):
    d, reality = {}, {}
    for line in (cfg or "").splitlines():
        if ":" not in line: continue
        # 仅将 key 设为小写，严格保护 Base64 value 的大小写
        raw_k, raw_v = line.split(":", 1)
        k = raw_k.strip().lower()
        v = raw_v.strip()
        if not k or not v: continue
        
        if k == "reality-opts":
            for part in v.strip("{}").split(","):
                if ":" in part:
                    rk_raw, rv_raw = part.split(":", 1)
                    rk = rk_raw.strip().lower().replace("-", "_")
                    rv = rv_raw.strip()
                    reality[rk] = rv
        else:
            d[k] = v
            
    return {**d, "reality": reality} if d.get("type") == "vless" and d.get("server") else None

def parse_config(cfg: str):
    if not cfg: return None
    low = cfg.lower()
    if "type: vless" in low:
        if v := parse_vless_config(cfg): return {"kind": "vless", "data": v}
    if "proxy =" in low or "[proxy]" in low:
        proto, host, port, pwd, sni = parse_leaf_trojan(cfg)
        if proto: return {"kind": "trojan", "data": {"host": host, "port": port, "password": pwd, "sni": sni}}
    return None

def make_vless_link(server, port, uuid, flow, sni, fp, pbk, sid, name) -> str:
    params = {"encryption": "none", "security": "reality", "type": "tcp"}
    if sni: params["sni"] = sni
    if fp: params["fp"] = fp
    if pbk: params["pbk"] = pbk
    if sid: params["sid"] = sid
    if flow: params["flow"] = flow
    q = urllib.parse.urlencode(params)
    return f"vless://{uuid}@{server}:{port}?{q}#{urllib.parse.quote(name)}"

def make_trojan_link(name, host, port, password, sni) -> str:
    q = urllib.parse.urlencode({"sni": sni, "security": "tls", "type": "tcp"})
    return f"trojan://{urllib.parse.quote(password, safe='')}@{host}:{port}?{q}#{urllib.parse.quote(name)}"

def fetch_one_node(nd: dict, token: str, imei: str, idx: int, total: int) -> dict | None:
    node_id, cc = nd.get("nodeId"), nd.get("countryCode")
    try:
        d = api_request("/nodes/vipConnect", "POST", {"nodeId": node_id}, token, imei)
        if not isinstance(d, dict) or not d.get("configFile"): 
            return None
            
        cfg = parse_config(d.get("configFile", ""))
        if not cfg: 
            return None
            
        c = cfg["data"]
        rec = {"kind": cfg["kind"], "countryCode": cc}
        
        if cfg["kind"] == "trojan":
            rec.update({"host": c.get("host"), "port": c.get("port"), "password": c.get("password"), "sni": c.get("sni")})
        elif cfg["kind"] == "vless":
            rec.update({
                "host": c.get("server"), "port": c.get("port"), "uuid": c.get("uuid"),
                "flow": c.get("flow"), "sni": c.get("servername"), "fp": c.get("client-fingerprint"),
                "pbk": c.get("reality", {}).get("public_key") or "", 
                "sid": c.get("reality", {}).get("short_id") or ""
            })
            
        with _PRINT_LOCK:
            print(f"\r进度: {idx}/{total} | {cc} {rec.get('host')} -> OK", end="", flush=True)
        return rec
    except Exception:
        with _PRINT_LOCK:
            print(f"\r进度: {idx}/{total} | {cc} -> FAIL", end="", flush=True)
        return None

# ================================================================ 主函数
def main():
    # 1. 初始化模块
    _init_modules()
    print(f"[+] 初始化加密模块完成，当前识别引擎: {USE_OCR_ENGINE.upper() if USE_OCR_ENGINE else 'NONE'}")
    
    # 2. 生成设备与虚拟账号
    email = gen_email()
    password = gen_password()
    imei = gen_imei()
    print(f"[+] 生成虚拟身份 -> 邮箱: {email} | IMEI: {imei}")
    
    # 3. 自动识别验证码并注册
    print("[1/4] 正在拉取图形验证码并自动识别注册...")
    token = auto_register_with_captcha(email, password, imei)
    print(f"      注册成功! 拿到有效 Token: {token[:16]}...")
    
    # 4. 领取福利 (若支持)
    print("[2/4] 检查并领取每日福利...")
    try:
        cd = api_request("/welfare/countdown", "GET", {}, token, imei)
        if isinstance(cd, dict) and cd.get("canClaim") is True:
            print("      检测到可领取福利，正在领取...")
            cl = api_request("/welfare/claim", "POST", {}, token, imei)
            print(f"      领取结果: {str(cl)[:100]}")
        else:
            print(f"      当前无需领取或不可领取 (state: {cd.get('state') if isinstance(cd, dict) else 'unknown'})")
    except Exception as ex:
        print(f"      福利检查/领取异常 (已跳过): {ex}")
        
    # 5. 拉取全量节点列表
    print("[3/4] 获取全量节点列表...")
    nodes = api_request("/nodes/list/all?supportSubscriptionNode=1", "GET", {}, token, imei)
    if not isinstance(nodes, list):
        raise RuntimeError(f"节点列表获取失败: {str(nodes)[:200]}")
    print(f"      列表获取成功，共 {len(nodes)} 个节点，并发解析中...")
    print("-" * 50)
    
    # 6. 并发拉取每个节点真实连接配置
    details = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = {executor.submit(fetch_one_node, nd, token, imei, i, len(nodes)): i for i, nd in enumerate(nodes, 1)}
        for fut in as_completed(futures):
            if res := fut.result():
                details.append(res)
                
    print("\n" + "-" * 50)
    print(f"[4/4] 节点解析完成: 成功 {len(details)} / 失败 {len(nodes) - len(details)}")
    
    # 7. 导出通用链接文本
    links = []
    for d in details:
        name = f"{d['countryCode'].upper()}-{d['host']}"
        if d["kind"] == "trojan":
            links.append(make_trojan_link(name, d["host"], d["port"], d["password"], d.get("sni") or d["host"]))
        elif d["kind"] == "vless":
            links.append(make_vless_link(
                d["host"], d["port"], d["uuid"], d.get("flow") or "xtls-rprx-vision",
                d.get("sni") or d["host"], d.get("fp") or "chrome", 
                d.get("pbk"), d.get("sid"), name
            ))
            
    os.makedirs(OUT_DIR, exist_ok=True)
    output_path = os.path.join(OUT_DIR, OUTPUT_FILE)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(links) + "\n" if links else "")
        
    kinds = Counter(d.get("kind") for d in details)
    print("\n" + "=" * 50)
    print("[+] 全流程自动执行完毕！")
    print(f"[+] 协议分布统计: {dict(kinds)}")
    print(f"[+] 节点已导出至: {os.path.abspath(output_path)}")
    print(f"[+] 凭据留存备查 -> Token: {token} | IMEI: {imei}")

if __name__ == "__main__":
    main()
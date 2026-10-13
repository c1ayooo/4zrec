# 用友移动管理系统pk_objSQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-移动系统管理"`
- **请求**：`POST /maportal/appmanager/save HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 202`

**请求体 / payload**
```
pk_obj=1
```

**其他**
- 用友移动管理系统pk\_obj SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友移动系统管理系统
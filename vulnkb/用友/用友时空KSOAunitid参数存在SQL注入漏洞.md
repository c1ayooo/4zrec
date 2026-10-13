# 用友时空KSOAunitid参数存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友时空 KSOA"`
- **请求**：`GET /servlet/com.sksoft.v8.trans.servlet.TaskRequestServlet?unitid=1 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=42640D8FBEC9198A7FDF8F90DABCDBB4`

**请求体 / payload**
```

```

**其他**
- 用友时空KSOA unitid参数存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友时空KSOA
